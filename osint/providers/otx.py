from __future__ import annotations

import os
from urllib.parse import quote

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http

_KIND = {
    IndicatorType.IP: "IPv4",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.HASH: "file",
    IndicatorType.URL: "url",
}


class OTX(Provider):
    id = "otx"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        kind = _KIND.get(ind.type, "hostname")
        if ind.type == IndicatorType.IP and ":" in ind.value:
            kind = "IPv6"
        target = quote(ind.value, safe="")
        return await http_get(
            ctx,
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{target}/general",
            headers={"X-OTX-API-KEY": key},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            return ParsedResult(summary="OTX request failed.", status=st)
        data = json_body(raw) or {}
        pulse = (data.get("pulse_info") or {}).get("count") or 0
        facts = [Fact("Pulses", str(pulse))]
        if data.get("asn"):
            facts.append(Fact("ASN", str(data.get("asn"))))
        if data.get("country_name"):
            facts.append(Fact("Country", str(data.get("country_name"))))
        related = []
        for p in ((data.get("pulse_info") or {}).get("pulses") or [])[:5]:
            name = p.get("name")
            if name:
                related.append(Related(IndicatorType.DOMAIN, str(name)[:80], "member_of_family"))
        tags = []
        for p in ((data.get("pulse_info") or {}).get("pulses") or [])[:4]:
            tags.extend(str(t) for t in (p.get("tags") or [])[:3])
        summary = f"{pulse} OTX pulses" if pulse else "No OTX pulses (unknown, not clean)"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags[:8],
            related=[],  # pulse names are not indicators
            score=float(pulse),
            status=ResultStatus.OK,
        )


register(OTX())
