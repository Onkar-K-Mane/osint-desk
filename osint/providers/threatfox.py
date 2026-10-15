from __future__ import annotations

import os

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_post, json_body, register, status_from_http


class ThreatFox(Provider):
    id = "threatfox"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        headers = {}
        if key:
            headers["Auth-Key"] = key
        if ind.type == IndicatorType.HASH:
            payload = {"query": "search_hash", "hash": ind.value}
        else:
            payload = {"query": "search_ioc", "search_term": ind.value}
        return await http_post(
            ctx, "https://threatfox-api.abuse.ch/api/v1/", json_payload=payload, headers=headers
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if raw.status_code in (401, 403):
            return ParsedResult(
                summary="ThreatFox requires a free Auth-Key.",
                status=ResultStatus.NO_KEY,
            )
        data = json_body(raw) or {}
        q = data.get("query_status")
        if q in {"no_result", "not_found"}:
            return ParsedResult(
                summary="Not on ThreatFox (unknown — not clean).",
                status=ResultStatus.OK,
                score=0.0,
            )
        if st != ResultStatus.OK:
            return ParsedResult(summary="ThreatFox request failed.", status=st)
        rows = data.get("data") or []
        if not rows:
            return ParsedResult(summary="Not on ThreatFox (unknown — not clean).", status=ResultStatus.OK, score=0.0)
        row = rows[0]
        malware = row.get("malware") or row.get("threat_type") or ""
        ioc = row.get("ioc") or ind.value
        facts = [Fact("Malware", str(malware))] if malware else []
        if row.get("threat_type"):
            facts.append(Fact("Threat type", str(row.get("threat_type"))))
        if row.get("confidence_level") is not None:
            facts.append(Fact("Confidence", str(row.get("confidence_level"))))
        if row.get("first_seen"):
            facts.append(Fact("First seen", str(row.get("first_seen"))))
        tags = [str(t) for t in (row.get("tags") or []) if t][:8]
        related = []
        for extra in rows[1:6]:
            eioc = extra.get("ioc")
            ioc_type = extra.get("ioc_type")
            if eioc and ioc_type in {"ip:port", "ip"}:
                related.append(Related(IndicatorType.IP, str(eioc).split(":")[0], "communicates_with"))
            elif eioc and ioc_type in {"domain", "url"}:
                related.append(Related(IndicatorType.DOMAIN if ioc_type == "domain" else IndicatorType.URL, str(eioc), "communicates_with"))
        summary = f"ThreatFox: {malware}" if malware else f"ThreatFox hit ({ioc})"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            related=related[:8],
            score=1.0,
            status=ResultStatus.OK,
        )


register(ThreatFox())
