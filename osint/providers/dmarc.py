from __future__ import annotations

from osint.models import Fact, Indicator, ParsedResult, RawResponse, ResultStatus
from osint.providers.base import Provider, http_get, json_body, register, status_from_http


class DmarcSpf(Provider):
    id = "dmarc_spf"

    async def fetch(self, ind: Indicator, ctx) -> RawResponse:
        # Fetch both TXT for the domain and _dmarc. Combine client-side; first call is SPF-ish TXT,
        # second we piggy-back by concatenating JSON in parse... we issue _dmarc first as the
        # canonical record, then SPF from the apex TXT.
        dmarc = await http_get(
            ctx,
            "https://cloudflare-dns.com/dns-query",
            headers={"Accept": "application/dns-json"},
            params={"name": f"_dmarc.{ind.value}", "type": "TXT"},
        )
        spf = await http_get(
            ctx,
            "https://cloudflare-dns.com/dns-query",
            headers={"Accept": "application/dns-json"},
            params={"name": ind.value, "type": "TXT"},
        )
        # Merge into a synthetic JSON body the parser understands.
        import json

        body = json.dumps(
            {
                "dmarc": json_body(dmarc) or {"error": dmarc.error, "Status": dmarc.status_code},
                "spf": json_body(spf) or {"error": spf.error, "Status": spf.status_code},
            }
        ).encode("utf-8")
        code = 200 if (dmarc.status_code == 200 or spf.status_code == 200) else (dmarc.status_code or spf.status_code)
        return RawResponse(status_code=code, body=body, url="https://cloudflare-dns.com/dns-query")

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        st = status_from_http(raw)
        data = json_body(raw) or {}
        if st != ResultStatus.OK and not data:
            return ParsedResult(summary="DoH lookup failed.", status=st)

        def txts(blob: dict) -> list[str]:
            out = []
            for ans in blob.get("Answer") or []:
                d = str(ans.get("data") or "").strip().strip('"')
                d = d.replace('" "', "").replace('"', "")
                if d:
                    out.append(d)
            return out

        dmarc_txts = txts(data.get("dmarc") or {})
        spf_txts = [t for t in txts(data.get("spf") or {}) if t.lower().startswith("v=spf1")]
        dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), "")
        spf = spf_txts[0] if spf_txts else ""
        facts = []
        policy = ""
        if dmarc:
            facts.append(Fact("DMARC", dmarc[:180]))
            for part in dmarc.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part.split("=", 1)[-1].strip()
                    facts.append(Fact("Policy", policy))
        else:
            facts.append(Fact("DMARC", "none published"))
        if spf:
            facts.append(Fact("SPF", spf[:180]))
        else:
            facts.append(Fact("SPF", "none published"))
        bits = []
        if policy:
            bits.append(f"p={policy}")
        else:
            bits.append("no DMARC")
        bits.append("SPF set" if spf else "no SPF")
        return ParsedResult(
            summary=" · ".join(bits),
            facts=facts[:5],
            tags=[f"dmarc-{policy}"] if policy else ["no-dmarc"],
            status=ResultStatus.OK,
        )


register(DmarcSpf())
