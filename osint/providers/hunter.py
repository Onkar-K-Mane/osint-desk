from __future__ import annotations

import os

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class Hunter(Provider):
    id = "hunter"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        if ind.type == IndicatorType.EMAIL:
            return await http_get(
                ctx,
                "https://api.hunter.io/v2/email-verifier",
                params={"email": ind.value, "api_key": key},
            )
        return await http_get(
            ctx,
            "https://api.hunter.io/v2/domain-search",
            params={"domain": ind.value, "api_key": key, "limit": 5},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if st != ResultStatus.OK:
            return ParsedResult(summary="Hunter.io request failed.", status=st)
        err = data.get("errors")
        if err:
            msg = err[0].get("details") if isinstance(err, list) and err else str(err)
            return ParsedResult(summary=str(msg)[:200], status=ResultStatus.ERROR)
        payload = data.get("data") or {}
        facts = []
        if ind.type == IndicatorType.EMAIL:
            status_s = payload.get("status") or payload.get("result") or ""
            facts.append(Fact("Status", str(status_s)))
            if payload.get("score") is not None:
                facts.append(Fact("Score", str(payload.get("score"))))
            if payload.get("disposable") is not None:
                facts.append(Fact("Disposable", str(payload.get("disposable"))))
            if payload.get("accept_all") is not None:
                facts.append(Fact("Accept-all", str(payload.get("accept_all"))))
            if payload.get("smtp_check") is not None:
                facts.append(Fact("SMTP", str(payload.get("smtp_check"))))
            summary = f"Hunter: {status_s or 'verified'}"
        else:
            org = payload.get("organization") or ""
            pattern = payload.get("pattern") or ""
            n = payload.get("emails") or []
            if org:
                facts.append(Fact("Organization", str(org)))
            if pattern:
                facts.append(Fact("Email pattern", str(pattern)))
            facts.append(Fact("Indexed mailboxes", str(len(n) if isinstance(n, list) else n)))
            if payload.get("disposable") is not None:
                facts.append(Fact("Disposable", str(payload.get("disposable"))))
            summary = f"Hunter domain · {len(n) if isinstance(n, list) else n} indexed"
            if org:
                summary += f" ({org})"
        return ParsedResult(summary=summary, facts=facts[:5], status=ResultStatus.OK)


register(Hunter())
