from __future__ import annotations

import os
from urllib.parse import quote

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class APIVoid(Provider):
    id = "apivoid"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        if ind.type == IndicatorType.IP:
            url = f"https://api.apivoid.com/v2/ip-reputation?key={key}&ip={quote(ind.value)}"
        elif ind.type == IndicatorType.DOMAIN:
            url = f"https://api.apivoid.com/v2/domain-reputation?key={key}&host={quote(ind.value)}"
        else:
            url = f"https://api.apivoid.com/v2/url-reputation?key={key}&url={quote(ind.value, safe='')}"
        return await http_get(ctx, url)

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if st != ResultStatus.OK:
            return ParsedResult(summary="APIVoid request failed.", status=st)
        err = (data.get("error") or {}).get("message") if isinstance(data.get("error"), dict) else data.get("error")
        if err:
            return ParsedResult(summary=str(err)[:200], status=ResultStatus.ERROR)
        data = data.get("data") or data
        report = data.get("report") or data
        score = report.get("risk_score", {}).get("result") if isinstance(report.get("risk_score"), dict) else report.get("risk_score")
        try:
            score_n = float(score) if score is not None else 0.0
        except (TypeError, ValueError):
            score_n = 0.0
        bl = report.get("blacklists") or report.get("blacklist_detections") or {}
        detections = bl.get("detections") if isinstance(bl, dict) else None
        facts = []
        if score is not None:
            facts.append(Fact("Risk score", str(score)))
        if detections is not None:
            facts.append(Fact("Blacklist hits", str(detections)))
        engines = bl.get("engines") if isinstance(bl, dict) else None
        if isinstance(engines, dict):
            hits = [k for k, v in engines.items() if v.get("detected")]
            if hits:
                facts.append(Fact("Lists", ", ".join(hits[:4])))
        summary = f"APIVoid risk {int(score_n)}"
        if detections:
            summary += f", {detections} blacklist hits"
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            score=score_n,
            status=ResultStatus.OK,
        )


register(APIVoid())
