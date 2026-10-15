from __future__ import annotations

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class GeoASN(Provider):
    id = "geoasn"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        return await http_get(ctx, f"https://ipwho.is/{ind.value}")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if st != ResultStatus.OK or data.get("success") is False:
            return ParsedResult(summary="No geo/ASN data.", status=ResultStatus.NOT_FOUND)
        conn = data.get("connection") or {}
        org = conn.get("org") or data.get("org") or ""
        asn = conn.get("asn") or data.get("asn") or ""
        isp = conn.get("isp") or ""
        country = data.get("country") or ""
        cc = data.get("country_code") or ""
        city = data.get("city") or ""
        facts = []
        if asn:
            facts.append(Fact("ASN", str(asn)))
        if org:
            facts.append(Fact("Org", str(org)))
        if isp and isp != org:
            facts.append(Fact("ISP", str(isp)))
        if country:
            facts.append(Fact("Country", f"{country} ({cc})" if cc else country))
        if city:
            facts.append(Fact("City", str(city)))
        if data.get("connection", {}).get("domain"):
            facts.append(Fact("Domain", str(data["connection"]["domain"])))
        related = []
        summary = " · ".join(x for x in [f"AS{asn}" if asn else "", org, country] if x)
        return ParsedResult(
            summary=summary or "Geo/ASN lookup",
            facts=facts[:5],
            tags=[t for t in [str(conn.get("type") or "")] if t],
            related=related,
            status=ResultStatus.OK,
        )


register(GeoASN())
