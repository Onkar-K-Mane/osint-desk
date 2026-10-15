from __future__ import annotations

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class InternetDB(Provider):
    id = "internetdb"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        return await http_get(ctx, f"https://internetdb.shodan.io/{ind.value}")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            return ParsedResult(
                summary="No InternetDB record (not scanned, or empty).",
                status=ResultStatus.NOT_FOUND if raw.status_code == 404 else st,
            )
        data = json_body(raw) or {}
        ports = data.get("ports") or []
        hostnames = data.get("hostnames") or []
        tags = [str(t) for t in (data.get("tags") or [])]
        vulns = data.get("vulns") or []
        facts = []
        if ports:
            facts.append(Fact("Open ports", ", ".join(str(p) for p in ports[:12])))
        if hostnames:
            facts.append(Fact("Hostnames", ", ".join(hostnames[:6])))
        if vulns:
            facts.append(Fact("CVEs", ", ".join(str(v) for v in vulns[:6])))
        if cpes := data.get("cpes"):
            facts.append(Fact("CPEs", ", ".join(str(c) for c in cpes[:4])))
        related = [
            Related(IndicatorType.DOMAIN, h.lower().lstrip("*."), "resolves_to")
            for h in hostnames[:8]
            if "." in h and "*" not in h
        ]
        summary = "No open-port data" if not ports else f"Open ports {', '.join(str(p) for p in ports[:8])}"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            related=related,
            status=ResultStatus.OK,
        )


register(InternetDB())
