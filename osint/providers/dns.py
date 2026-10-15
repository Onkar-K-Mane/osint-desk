from __future__ import annotations

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http

_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


class DNS(Provider):
    id = "dns"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        # Bundle A as the primary fetch; parse will be for A. Orchestrator runs one fetch.
        # We sequentially query a few types inside fetch and concatenate JSON.
        import json

        combined = {}
        first_raw = None
        for t in _TYPES:
            raw = await http_get(
                ctx,
                "https://cloudflare-dns.com/dns-query",
                headers={"Accept": "application/dns-json"},
                params={"name": ind.value, "type": t},
            )
            if first_raw is None:
                first_raw = raw
            body = json_body(raw)
            combined[t] = body
            if t == "A" and raw.status_code and raw.status_code >= 400:
                return raw
        payload = json.dumps(combined).encode("utf-8")
        return RawResponse(
            status_code=200,
            body=payload,
            headers={"content-type": "application/json"},
            url="https://cloudflare-dns.com/dns-query",
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if st != ResultStatus.OK:
            return ParsedResult(summary="DNS lookup failed.", status=st)
        facts: list[Fact] = []
        related: list[Related] = []
        tags: list[str] = []
        # Combined form {A: {...}, MX: {...}} or a single DoH response
        sections = data if "A" in data or "MX" in data else {"A": data}
        for t, body in sections.items():
            if not isinstance(body, dict):
                continue
            answers = body.get("Answer") or []
            vals = []
            for a in answers:
                d = str(a.get("data") or "").rstrip(".")
                if not d:
                    continue
                vals.append(d)
                if t in {"A", "AAAA"}:
                    related.append(Related(IndicatorType.IP, d, "resolves_to"))
                if t == "MX":
                    host = d.split(" ", 1)[-1]
                    related.append(Related(IndicatorType.DOMAIN, host.lower(), "resolves_to"))
                if t == "NS":
                    related.append(Related(IndicatorType.DOMAIN, d.lower(), "resolves_to"))
            if vals:
                facts.append(Fact(t, ", ".join(vals[:6])))
            if t == "TXT":
                joined = " ".join(vals).upper()
                if "SPF" in joined or "V=SPF1" in joined:
                    tags.append("spf")
                if "DKIM" in joined:
                    tags.append("dkim")
                if "DMARC" in joined or "V=DMARC1" in joined:
                    tags.append("dmarc")
        a_recs = [r.value for r in related if r.relation == "resolves_to" and r.type == IndicatorType.IP]
        summary = f"A {', '.join(a_recs[:4])}" if a_recs else "No A records"
        return ParsedResult(
            summary=summary,
            facts=facts[:6],
            tags=tags,
            related=related[:12],
            status=ResultStatus.OK,
        )


register(DNS())
