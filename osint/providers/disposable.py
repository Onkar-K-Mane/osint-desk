from __future__ import annotations

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.policy import disposable_domains
from osint.providers.base import Provider, register


class DisposableEmail(Provider):
    id = "disposable_email"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        domain = (ind.email_domain or "").lower()
        hit = domain in disposable_domains()
        return RawResponse(status_code=200, body=b"hit" if hit else b"miss", url="local://disposable")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        hit = raw.body == b"hit"
        domain = ind.email_domain or ""
        if hit:
            return ParsedResult(
                summary=f"{domain} is a known disposable-mail provider.",
                facts=[Fact("Domain", domain), Fact("Disposable", "yes")],
                tags=["disposable"],
                status=ResultStatus.OK,
            )
        return ParsedResult(
            summary=f"{domain} is not on the local disposable-mail list.",
            facts=[Fact("Domain", domain), Fact("Disposable", "no")],
            status=ResultStatus.OK,
        )


register(DisposableEmail())
