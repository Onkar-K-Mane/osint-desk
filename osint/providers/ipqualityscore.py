from __future__ import annotations

import os
from urllib.parse import quote

from osint.models import Fact, Indicator, IndicatorType, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class IPQualityScore(Provider):
    id = "ipqualityscore"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        key = os.environ.get(ctx.spec.key_env or "", "")
        if ind.type == IndicatorType.IP:
            path = f"https://www.ipqualityscore.com/api/json/ip/{key}/{ind.value}"
        elif ind.type == IndicatorType.EMAIL:
            path = f"https://www.ipqualityscore.com/api/json/email/{key}/{quote(ind.value, safe='')}"
        else:
            path = f"https://www.ipqualityscore.com/api/json/url/{key}/{quote(ind.value, safe='')}"
        return await http_get(ctx, path)

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if not data.get("success", True) and data.get("message"):
            return ParsedResult(summary=str(data.get("message"))[:200], status=st if st != ResultStatus.OK else ResultStatus.ERROR)
        if st != ResultStatus.OK:
            return ParsedResult(summary="IPQS request failed.", status=st)
        score = data.get("fraud_score")
        try:
            score_n = float(score) if score is not None else 0.0
        except (TypeError, ValueError):
            score_n = 0.0
        facts = []
        if score is not None:
            facts.append(Fact("Fraud score", str(score)))
        flags = []
        for k, label in (
            ("proxy", "Proxy"),
            ("vpn", "VPN"),
            ("tor", "Tor"),
            ("bot_status", "Bot"),
            ("recent_abuse", "Recent abuse"),
            ("disposable", "Disposable"),
            ("valid", "Valid mailbox"),
            ("smtp_score", "SMTP score"),
            ("overall_score", "Deliverability"),
            ("isp", "ISP"),
            ("organization", "Org"),
            ("country_code", "Country"),
            ("malware", "Malware"),
            ("phishing", "Phishing"),
        ):
            if k in data and data[k] not in (None, "", False):
                facts.append(Fact(label, str(data[k])))
            if data.get(k) is True and k in {"proxy", "vpn", "tor", "bot_status", "recent_abuse", "disposable", "malware", "phishing"}:
                flags.append(k)
        summary = f"IPQS fraud score {int(score_n)}"
        if flags:
            summary += " · " + ", ".join(flags[:4])
        return ParsedResult(
            summary=summary,
            facts=facts[:5],
            tags=flags[:8],
            score=score_n,
            status=ResultStatus.OK,
        )


register(IPQualityScore())
