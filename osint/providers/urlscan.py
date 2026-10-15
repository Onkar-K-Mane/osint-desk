from __future__ import annotations

import os

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class UrlscanSearch(Provider):
    id = "urlscan_search"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        headers = {}
        if key:
            headers["API-Key"] = key
        if ind.type == IndicatorType.DOMAIN:
            q = f"domain:{ind.value}"
        elif ind.type == IndicatorType.IP:
            q = f'page.ip:"{ind.value}"'
        elif ind.type == IndicatorType.HASH:
            q = f"hash:{ind.value}"
        else:
            q = f'page.url:"{ind.value}"'
        return await http_get(
            ctx,
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params={"q": q, "size": 5},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            return ParsedResult(summary="urlscan search failed.", status=st)
        data = json_body(raw) or {}
        total = data.get("total") or len(data.get("results") or [])
        results = data.get("results") or []
        facts = [Fact("Prior scans", str(total))]
        related: list[Related] = []
        tags = []
        malicious = False
        for item in results[:3]:
            page = item.get("page") or {}
            if ip := page.get("ip"):
                related.append(Related(IndicatorType.IP, ip, "resolves_to"))
                facts.append(Fact("Last IP", ip))
            if domain := page.get("domain"):
                related.append(Related(IndicatorType.DOMAIN, str(domain).lower(), "redirects_to"))
            verdict = (item.get("verdicts") or {}).get("overall") or {}
            if verdict.get("malicious"):
                tags.append("urlscan-malicious")
                malicious = True
        summary = f"{total} prior scans" if total else "No prior urlscan results (unknown, not clean)"
        if malicious:
            summary = f"{total} prior scans — urlscan marked at least one malicious"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            related=related[:8],
            status=ResultStatus.OK,
            score=1.0 if malicious else None,
        )


register(UrlscanSearch())
