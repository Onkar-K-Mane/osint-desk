from __future__ import annotations

import os

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class HybridAnalysis(Provider):
    id = "hybrid_analysis"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        return await http_get(
            ctx,
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            headers={
                "api-key": key,
                "User-Agent": "Falcon Sandbox",
                "Accept": "application/json",
            },
            params={"hash": ind.value},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if raw.status_code == 404 or st == ResultStatus.NOT_FOUND:
            return ParsedResult(summary="Not in Hybrid Analysis corpus.", status=ResultStatus.NOT_FOUND)
        if st != ResultStatus.OK:
            return ParsedResult(summary="Hybrid Analysis request failed.", status=st)
        data = json_body(raw)
        rows = data if isinstance(data, list) else (data or {}).get("result") or []
        if not rows:
            return ParsedResult(summary="Not in Hybrid Analysis corpus.", status=ResultStatus.NOT_FOUND)
        row = rows[0] if isinstance(rows, list) else rows
        verdict = (row.get("verdict") or row.get("threat_level_human") or "").lower()
        score = row.get("threat_score")
        family = row.get("vx_family") or row.get("malware_family") or ""
        facts = []
        if verdict:
            facts.append(Fact("Verdict", str(row.get("verdict") or verdict)))
        if score is not None:
            facts.append(Fact("Threat score", str(score)))
        if family:
            facts.append(Fact("Family", str(family)))
        if row.get("type"):
            facts.append(Fact("Type", str(row.get("type"))))
        tags = [str(t) for t in (row.get("tags") or []) if t][:8]
        if family:
            tags.insert(0, str(family))
        classification = "malicious" if verdict in {"malicious", "suspicious"} or (isinstance(score, (int, float)) and score >= 80) else (
            "suspicious" if verdict == "suspicious" or (isinstance(score, (int, float)) and score >= 40) else (
                "benign" if verdict in {"no specific threat", "whitelisted", "clean", "benign"} else "unknown"
            )
        )
        if verdict in {"malicious"}:
            classification = "malicious"
        summary = f"Hybrid Analysis: {verdict or 'report found'}"
        if family:
            summary += f" ({family})"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=tags,
            classification=classification,
            status=ResultStatus.OK,
        )


register(HybridAnalysis())
