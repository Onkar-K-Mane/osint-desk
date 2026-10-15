from __future__ import annotations

import os

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class Triage(Provider):
    id = "triage"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        q = ind.value
        if ind.hash_algo:
            q = f"{ind.hash_algo}:{ind.value}"
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return await http_get(
            ctx,
            "https://tria.ge/api/v0/search",
            headers=headers,
            params={"query": q},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st == ResultStatus.NOT_FOUND:
            return ParsedResult(summary="Not in Triage corpus.", status=ResultStatus.NOT_FOUND)
        if st != ResultStatus.OK:
            return ParsedResult(summary="Triage request failed.", status=st)
        data = json_body(raw) or {}
        rows = data.get("data") or data.get("reports") or []
        if isinstance(data, list):
            rows = data
        if not rows:
            return ParsedResult(summary="Not in Triage corpus.", status=ResultStatus.NOT_FOUND)
        row = rows[0]
        score = row.get("score")
        family = ""
        tags = []
        analysis = row.get("analysis") or {}
        for t in (row.get("tags") or analysis.get("tags") or [])[:8]:
            tags.append(str(t))
            if str(t).startswith("family:") or str(t).startswith("malware:"):
                family = str(t).split(":", 1)[-1]
        facts = []
        if score is not None:
            facts.append(Fact("Score", str(score)))
        if family:
            facts.append(Fact("Family", family))
        if row.get("id") or row.get("sample"):
            facts.append(Fact("Sample", str(row.get("id") or row.get("sample"))))
        status_s = (row.get("status") or row.get("verdict") or "").lower()
        classification = "unknown"
        try:
            sc = float(score) if score is not None else -1
        except (TypeError, ValueError):
            sc = -1
        if sc >= 8 or status_s in {"malicious"}:
            classification = "malicious"
        elif sc >= 5 or status_s in {"suspicious"}:
            classification = "suspicious"
        elif sc == 0 or status_s in {"benign", "clean"}:
            classification = "benign"
        summary = f"Triage corpus hit (score {score})" if score is not None else "Triage corpus hit"
        if family:
            summary += f" · {family}"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            classification=classification,
            status=ResultStatus.OK,
        )


register(Triage())
