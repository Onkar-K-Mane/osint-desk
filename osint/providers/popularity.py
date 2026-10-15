from __future__ import annotations

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.policy import top_domains
from osint.providers.base import Provider, register
from osint.psl import default_psl


class Popularity(Provider):
    id = "popularity"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        # Local list — no network.
        registrable = default_psl().registrable_domain(ind.value) or ind.value
        hit = ind.value in top_domains() or registrable in top_domains()
        body = b"hit" if hit else b"miss"
        return RawResponse(status_code=200, body=body, url="local://popularity")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        hit = raw.body == b"hit"
        registrable = default_psl().registrable_domain(ind.value) or ind.value
        if hit:
            return ParsedResult(
                summary=f"{registrable} is on the local top-site allowlist.",
                facts=[Fact("List", "local popularity / top sites"), Fact("Registrable", registrable)],
                tags=["allowlisted", "popular"],
                allowlist_hit=True,
                status=ResultStatus.OK,
            )
        return ParsedResult(
            summary="Not on the local top-site allowlist (unknown, not a reputation miss).",
            facts=[Fact("Registrable", registrable)],
            allowlist_hit=False,
            status=ResultStatus.OK,
        )


register(Popularity())
