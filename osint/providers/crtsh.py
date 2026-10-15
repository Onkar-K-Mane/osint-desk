from __future__ import annotations

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class CrtSh(Provider):
    id = "crtsh"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        return await http_get(
            ctx,
            "https://crt.sh/",
            params={"q": ind.value, "output": "json"},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if raw.status_code == 200 and not raw.body:
            return ParsedResult(summary="No certificates on crt.sh.", status=ResultStatus.NOT_FOUND)
        if st != ResultStatus.OK:
            return ParsedResult(summary="crt.sh request failed.", status=st)
        data = json_body(raw)
        if not isinstance(data, list) or not data:
            return ParsedResult(summary="No certificates on crt.sh.", status=ResultStatus.NOT_FOUND)
        names: set[str] = set()
        earliest = None
        latest = None
        issuers: set[str] = set()
        for row in data[:200]:
            for field in ("name_value", "common_name"):
                raw_n = row.get(field) or ""
                for n in str(raw_n).split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n and n != ind.value and "*" not in n:
                        names.add(n)
            nb = row.get("not_before")
            na = row.get("not_after")
            if nb and (earliest is None or nb < earliest):
                earliest = nb
            if na and (latest is None or na > latest):
                latest = na
            iss = row.get("issuer_name")
            if iss:
                issuers.add(str(iss)[:80])
        facts = [Fact("Certificates", str(len(data)))]
        if earliest:
            facts.append(Fact("Earliest not_before", str(earliest)[:19]))
        if latest:
            facts.append(Fact("Latest not_after", str(latest)[:19]))
        if issuers:
            facts.append(Fact("Issuer", next(iter(issuers))))
        if names:
            facts.append(Fact("Alt names (sample)", ", ".join(sorted(names)[:5])))
        related = [
            Related(IndicatorType.DOMAIN, n, "shares_cert")
            for n in sorted(names)
            if n.count(".") >= 1
        ][:12]
        summary = f"{len(data)} CT certificates"
        if earliest:
            summary += f", first {str(earliest)[:10]}"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            related=related,
            status=ResultStatus.OK,
        )


register(CrtSh())
