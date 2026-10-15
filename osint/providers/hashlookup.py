from __future__ import annotations

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class Hashlookup(Provider):
    id = "hashlookup"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        algo = ind.hash_algo or "sha256"
        # CIRCL uses md5 / sha1 / sha256
        if algo == "sha512":
            algo = "sha256"
        return await http_get(ctx, f"https://hashlookup.circl.lu/lookup/{algo}/{ind.value}")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        if raw.status_code == 404:
            return ParsedResult(
                summary="Not in CIRCL hashlookup (unknown — not clean).",
                status=ResultStatus.OK,
                allowlist_hit=False,
            )
        st = status_from_http(raw)
        if st != ResultStatus.OK:
            return ParsedResult(summary="hashlookup request failed.", status=st)
        data = json_body(raw) or {}
        if not data or data.get("message") == "Non existing hash":
            return ParsedResult(
                summary="Not in CIRCL hashlookup (unknown — not clean).",
                status=ResultStatus.OK,
                allowlist_hit=False,
            )
        facts = []
        for label, key in [
            ("File", "FileName"),
            ("Product", "Product"),
            ("Publisher", "FilePublisher"),
            ("Known", "hashlookup:trust"),
            ("Source", "source"),
        ]:
            if data.get(key) not in (None, ""):
                facts.append(Fact(label, str(data.get(key))))
        name = data.get("FileName") or data.get("Product") or "known file"
        return ParsedResult(
            summary=f"Known benign: {name}",
            facts=facts[:5],
            tags=["known-benign"],
            allowlist_hit=True,
            status=ResultStatus.OK,
        )


register(Hashlookup())
