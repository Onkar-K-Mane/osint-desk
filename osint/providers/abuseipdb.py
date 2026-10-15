from __future__ import annotations

import os
from datetime import datetime, timezone

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class AbuseIPDB(Provider):
    id = "abuseipdb"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        return await http_get(
            ctx,
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ind.value, "maxAgeInDays": 90, "verbose": True},
        )

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            msg = "AbuseIPDB request failed."
            if st == ResultStatus.NOT_FOUND:
                msg = "No record."
            return ParsedResult(summary=msg, status=st)
        data = (json_body(raw) or {}).get("data") or {}
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports") or 0
        last = data.get("lastReportedAt")
        facts = []
        for label, key in [
            ("Confidence", "abuseConfidenceScore"),
            ("Reports", "totalReports"),
            ("ISP", "isp"),
            ("Usage", "usageType"),
            ("Country", "countryCode"),
            ("Domain", "domain"),
            ("Whitelisted", "isWhitelisted"),
        ]:
            if data.get(key) not in (None, ""):
                facts.append(Fact(label, str(data.get(key))))
        last_dt = _parse_dt(last)
        summary = f"Confidence {score}%, {reports} reports"
        if last:
            summary += f", last {last}"
        tags = []
        if data.get("isTor"):
            tags.append("tor")
        if data.get("usageType"):
            tags.append(str(data.get("usageType")).lower().replace(" ", "-"))
        return ParsedResult(
            summary=summary,
            facts=facts[:6],
            tags=tags,
            last_seen=last_dt,
            score=float(score) if score is not None else 0.0,
            status=ResultStatus.OK,
        )


def _parse_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


register(AbuseIPDB())
