from __future__ import annotations

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class RDAP(Provider):
    id = "rdap"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        if ind.type == IndicatorType.IP:
            return await http_get(ctx, f"https://rdap.org/ip/{ind.value}")
        return await http_get(ctx, f"https://rdap.org/domain/{ind.value}")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            return ParsedResult(summary="No RDAP record.", status=st)
        data = json_body(raw) or {}
        facts: list[Fact] = []
        related: list[Related] = []
        name = data.get("name") or data.get("ldhName") or data.get("handle")
        if name:
            facts.append(Fact("Handle / name", str(name)))
        if start := data.get("startAddress"):
            end = data.get("endAddress") or ""
            facts.append(Fact("Netblock", f"{start} – {end}".strip(" –")))
        if cidr := data.get("cidr0_cidrs") or data.get("ipAddress"):
            facts.append(Fact("CIDR", str(cidr)[:80]))
        if country := data.get("country"):
            facts.append(Fact("Country", str(country)))
        if port43 := data.get("port43"):
            facts.append(Fact("WHOIS", str(port43)))
        entities = data.get("entities") or []
        for ent in entities[:4]:
            vcard = ent.get("vcardArray") or []
            fn = _vcard_fn(vcard)
            roles = ",".join(ent.get("roles") or [])
            if fn:
                facts.append(Fact(roles or "Entity", fn))
                if "registrar" in (ent.get("roles") or []):
                    related.append(Related(IndicatorType.DOMAIN, fn, "owned_by"))
        events = data.get("events") or []
        created = None
        for ev in events:
            if ev.get("eventAction") in {"registration", "last changed"}:
                facts.append(Fact(str(ev.get("eventAction")).title(), str(ev.get("eventDate", ""))[:19]))
                if ev.get("eventAction") == "registration":
                    created = str(ev.get("eventDate", ""))[:10]
        nameservers = [n.get("ldhName") for n in (data.get("nameservers") or []) if n.get("ldhName")]
        if nameservers:
            facts.append(Fact("Nameservers", ", ".join(nameservers[:4])))
        status = data.get("status") or []
        tags = [str(s) for s in status[:6]]
        summary = str(name or "RDAP record")
        if created:
            summary += f", registered {created}"
        return ParsedResult(summary=summary, facts=facts[:6], tags=tags, related=related[:6], status=ResultStatus.OK)


def _vcard_fn(vcard) -> str:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == "fn":
            return str(item[-1])
    return ""


register(RDAP())
