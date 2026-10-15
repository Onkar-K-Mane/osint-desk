"""SOC hunt strings from extracted indicators. Never includes private IPs."""

from __future__ import annotations

from typing import Any, Iterable

from osint.defang import defang, defang_url_scheme
from osint.models import Indicator, IndicatorType
from osint.policy import evaluate


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _or_field(field: str, values: list[str], style: str) -> str:
    if not values:
        return ""
    if style == "splunk":
        inner = " OR ".join(f'{field}="{_esc(v)}"' for v in values)
        return f"({inner})"
    if style == "kql":
        inner = ", ".join(f'"{_esc(v)}"' for v in values)
        return f"{field} in ({inner})"
    if style == "elastic":
        inner = " OR ".join(f'{field}:"{_esc(v)}"' for v in values)
        return f"({inner})"
    inner = "|".join(v.replace(".", r"\.") for v in values)
    return inner


def _public(indicators: Iterable[Indicator]) -> list[Indicator]:
    out = []
    for ind in indicators:
        pol = evaluate(ind)
        if not pol.allow_external and ind.type == IndicatorType.IP:
            continue
        out.append(ind)
    return out


def hunt_pack(indicators: Iterable[Indicator]) -> dict[str, Any]:
    inds = list(indicators)
    pub = _public(inds)
    by: dict[str, list[str]] = {"ip": [], "domain": [], "url": [], "hash": [], "email": []}
    for i in pub:
        by[i.type.value].append(i.value)

    splunk: list[str] = []
    kql: list[str] = []
    elastic: list[str] = []
    if by["ip"]:
        splunk.append(_or_field("src_ip", by["ip"], "splunk") + " OR " + _or_field("dest_ip", by["ip"], "splunk"))
        kql.append(_or_field("SrcIp", by["ip"], "kql") + " or " + _or_field("DstIp", by["ip"], "kql"))
        elastic.append(_or_field("source.ip", by["ip"], "elastic") + " OR " + _or_field("destination.ip", by["ip"], "elastic"))
    if by["domain"]:
        splunk.append(_or_field("query", by["domain"], "splunk") + " OR " + _or_field("url", by["domain"], "splunk"))
        kql.append(_or_field("DnsQuery", by["domain"], "kql") + " or " + _or_field("RemoteUrl", by["domain"], "kql"))
        elastic.append(_or_field("dns.question.name", by["domain"], "elastic") + " OR " + _or_field("url.domain", by["domain"], "elastic"))
    if by["url"]:
        splunk.append(_or_field("url", by["url"], "splunk"))
        kql.append(_or_field("Url", by["url"], "kql"))
        elastic.append(_or_field("url.full", by["url"], "elastic"))
    if by["hash"]:
        splunk.append(
            _or_field("file_hash", by["hash"], "splunk")
            + " OR "
            + _or_field("sha256", by["hash"], "splunk")
            + " OR "
            + _or_field("md5", by["hash"], "splunk")
        )
        kql.append(_or_field("SHA256", by["hash"], "kql") + " or " + _or_field("MD5", by["hash"], "kql"))
        elastic.append(_or_field("file.hash.sha256", by["hash"], "elastic") + " OR " + _or_field("file.hash.md5", by["hash"], "elastic"))
    if by["email"]:
        splunk.append(_or_field("sender", by["email"], "splunk") + " OR " + _or_field("recipient", by["email"], "splunk"))
        kql.append(_or_field("SenderFromAddress", by["email"], "kql"))
        elastic.append(_or_field("email.from.address", by["email"], "elastic"))

    defanged = []
    for i in inds:
        if i.type == IndicatorType.URL:
            defanged.append(f"{i.type.value}\t{defang_url_scheme(i.value)}")
        else:
            defanged.append(f"{i.type.value}\t{defang(i.value)}")

    grep = " ".join(i.value for i in pub) if pub else ""
    return {
        "splunk": " OR ".join(splunk) if splunk else "",
        "kql": " or ".join(kql) if kql else "",
        "elastic": " OR ".join(elastic) if elastic else "",
        "grep": grep,
        "defanged": "\n".join(defanged),
        "counts": {k: len(v) for k, v in by.items()},
        "skipped_private": len(inds) - len(pub),
    }
