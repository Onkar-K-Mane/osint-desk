from __future__ import annotations

import os

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class GreyNoise(Provider):
    id = "greynoise_community"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        return await http_get(
            ctx,
            f"https://api.greynoise.io/v3/community/{ind.value}",
            headers={"key": key, "Accept": "application/json"},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if raw.status_code == 404 or data.get("message") == "IP not observed":
            return ParsedResult(
                summary="Not seen by GreyNoise (unknown — not clean).",
                status=ResultStatus.OK,
                classification="unknown",
                score=None,
            )
        if st != ResultStatus.OK:
            return ParsedResult(summary="GreyNoise request failed.", status=st)
        classification = str(data.get("classification") or "unknown").lower()
        name = data.get("name") or data.get("riot") or ""
        noise = data.get("noise")
        riot = data.get("riot")
        facts = []
        if classification:
            facts.append(Fact("Classification", classification))
        if name:
            facts.append(Fact("Name", str(name)))
        if noise is not None:
            facts.append(Fact("Internet noise", str(noise)))
        if riot is not None:
            facts.append(Fact("RIOT", str(riot)))
        if data.get("last_seen"):
            facts.append(Fact("Last seen", str(data.get("last_seen"))))
        tags = []
        if riot:
            tags.append("known-benign-infrastructure")
            classification = "benign"
        if noise:
            tags.append("internet-scanner")
        summary = classification
        if name:
            summary += f" ({name})"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            classification=classification,
            allowlist_hit=bool(riot),
            status=ResultStatus.OK,
        )


register(GreyNoise())
