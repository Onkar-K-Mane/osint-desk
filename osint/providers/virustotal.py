from __future__ import annotations

import hashlib
import os

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http

_PATH = {
    IndicatorType.IP: "ip_addresses",
    IndicatorType.DOMAIN: "domains",
    IndicatorType.HASH: "files",
}


class VirusTotal(Provider):
    id = "virustotal"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        headers = {"x-apikey": key, "Accept": "application/json"}
        if ind.type == IndicatorType.URL:
            url_id = hashlib.sha256(ind.value.encode("utf-8")).hexdigest()
            return await http_get(ctx, f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        kind = _PATH.get(ind.type)
        if not kind:
            return RawResponse(status_code=400, body=b"", error="unsupported")
        return await http_get(ctx, f"https://www.virustotal.com/api/v3/{kind}/{ind.value}", headers=headers)

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            summary = "Not in VirusTotal." if st == ResultStatus.NOT_FOUND else "VirusTotal request failed."
            return ParsedResult(summary=summary, status=st)
        attrs = ((json_body(raw) or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious") or 0)
        sus = int(stats.get("suspicious") or 0)
        harm = int(stats.get("harmless") or 0)
        undet = int(stats.get("undetected") or 0)
        score = mal  # reputation uses engine counts
        facts = [
            Fact("Malicious engines", str(mal)),
            Fact("Suspicious engines", str(sus)),
            Fact("Harmless", str(harm)),
            Fact("Undetected", str(undet)),
        ]
        related: list[Related] = []
        if as_owner := attrs.get("as_owner") or attrs.get("registrar"):
            facts.append(Fact("Owner" if attrs.get("as_owner") else "Registrar", str(as_owner)))
        if country := attrs.get("country"):
            facts.append(Fact("Country", str(country)))
        if asn := attrs.get("asn"):
            facts.append(Fact("ASN", str(asn)))
        for name in (attrs.get("last_https_certificate", {}) or {}).get("extensions", {}).get("subject_alternative_name", [])[:5]:
            related.append(Related(IndicatorType.DOMAIN, str(name).lower(), "shares_cert"))
        for d in (attrs.get("contacted_domains") or [])[:5]:
            related.append(Related(IndicatorType.DOMAIN, str(d).lower(), "contacted"))
        popular = attrs.get("popular_threat_classification") or {}
        family = None
        if isinstance(popular, dict):
            suggested = popular.get("suggested_threat_label")
            if suggested:
                family = str(suggested)
                facts.append(Fact("Family", family))
        tags = list(attrs.get("tags") or [])[:8]
        if family:
            tags.append(family)
        summary = f"{mal} engines flag it"
        if sus:
            summary += f", {sus} suspicious"
        if as_owner := attrs.get("as_owner"):
            summary += f"; owner {as_owner}"
        return ParsedResult(
            summary=summary,
            facts=facts[:6],
            tags=[str(t) for t in tags],
            related=related[:12],
            score=float(mal if mal else (0.5 if sus else 0.0)),
            extra={"malicious": mal, "suspicious": sus},
            status=ResultStatus.OK,
        )


register(VirusTotal())
