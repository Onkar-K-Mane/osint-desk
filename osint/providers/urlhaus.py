from __future__ import annotations

import os

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, Related, ResultStatus
from osint.providers.base import Provider, http_post, json_body, register, status_from_http


class URLhaus(Provider):
    id = "urlhaus"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        headers = {}
        if key:
            headers["Auth-Key"] = key
        if ind.type == IndicatorType.HASH:
            return await http_post(
                ctx,
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data={"sha256_hash": ind.value} if len(ind.value) == 64 else {"md5_hash": ind.value},
                headers=headers,
            )
        if ind.type in {IndicatorType.DOMAIN, IndicatorType.IP}:
            return await http_post(
                ctx,
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": ind.value},
                headers=headers,
            )
        return await http_post(
            ctx,
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": ind.value},
            headers=headers,
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        q = data.get("query_status")
        if q in {"no_results", "invalid_url", "invalid_host", "no_result"}:
            return ParsedResult(
                summary="Not on URLhaus (unknown — not clean).",
                status=ResultStatus.OK,
                score=0.0,
            )
        if st != ResultStatus.OK:
            return ParsedResult(summary="URLhaus request failed.", status=st)
        if q != "ok":
            return ParsedResult(summary="Not on URLhaus (unknown — not clean).", status=ResultStatus.OK, score=0.0)
        threat = data.get("threat") or data.get("url_status") or data.get("file_type") or ""
        facts = []
        if threat:
            facts.append(Fact("Threat", str(threat)))
        if data.get("url_status"):
            facts.append(Fact("Status", str(data.get("url_status"))))
        if data.get("host"):
            facts.append(Fact("Host", str(data.get("host"))))
        if data.get("signature"):
            facts.append(Fact("Signature", str(data.get("signature"))))
        if data.get("date_added"):
            facts.append(Fact("Added", str(data.get("date_added"))))
        related: list[Related] = []
        host = data.get("host")
        if host and ind.type != IndicatorType.DOMAIN:
            related.append(Related(IndicatorType.DOMAIN, str(host).lower(), "hosted_on"))
        for payload in (data.get("payloads") or data.get("urls") or [])[:5]:
            sha = payload.get("response_sha256") or payload.get("sha256_hash")
            if sha:
                related.append(Related(IndicatorType.HASH, sha, "downloads"))
            url = payload.get("url")
            if url:
                related.append(Related(IndicatorType.URL, url, "listed_url"))
        tags = [str(t) for t in (data.get("tags") or []) if t][:8]
        summary = f"URLhaus: {threat}" if threat else "Listed on URLhaus"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            related=related[:8],
            score=1.0,
            status=ResultStatus.OK,
        )


register(URLhaus())
