"""One-click copyable investigation summary. Pure function over stored results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from osint.db import lookup_bundle, row_to_result
from osint.defang import defang, defang_url_scheme
from osint.models import ResultStatus, Verdict
from osint.orchestrator import compute_rollup
from osint.registry import get_registry

_TLP_ALLOWED = {"CLEAR", "GREEN", "AMBER", "RED"}


def tlp_prefix(tlp: str | None) -> str:
    t = (tlp or "CLEAR").strip().upper()
    if t.startswith("TLP:"):
        t = t[4:]
    if t not in _TLP_ALLOWED:
        t = "CLEAR"
    return f"TLP:{t}"


def _dt(s: str | None) -> str:
    if not s:
        return "unknown time"
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return s


def _age(queried_at: str | None) -> str | None:
    if not queried_at:
        return None
    try:
        dt = datetime.fromisoformat(queried_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        mins = int(delta.total_seconds() // 60)
        if mins < 5:
            return None
        if mins < 60:
            return f"{mins}m cache"
        hours = mins // 60
        if hours < 48:
            return f"{hours}h cache"
        return f"{hours // 24}d cache"
    except ValueError:
        return None


def _display_ioc(value: str, itype: str, raw: bool) -> str:
    if raw:
        return value
    if itype == "url":
        return defang_url_scheme(value)
    return defang(value)


def _combined_header(lookup_ids: list[str], fmt: str, raw_indicators: bool) -> str:
    mal = sus = ben = info = 0
    iocs: list[str] = []
    registry = get_registry()
    for lid in lookup_ids:
        bundle = lookup_bundle(lid)
        if not bundle:
            continue
        ind = bundle["indicator"]
        iocs.append(f"{_display_ioc(ind['value'], ind['type'], raw_indicators)} ({ind['type']})")
        results = []
        specs = {}
        for row in bundle["results"]:
            spec = registry.get(row["provider"])
            name = spec.name if spec else row["provider"]
            if spec:
                specs[spec.id] = spec
            results.append(row_to_result(row, name))
        roll = compute_rollup(results, specs)
        mal += roll.malicious
        sus += roll.suspicious
        ben += roll.benign
        info += roll.info
    line = (
        f"{len(iocs)} indicators · {mal} malicious · {sus} suspicious · "
        f"{ben} benign · {info} info"
    )
    if fmt == "text":
        return "COMBINED BATCH\n" + line + "\nIOCs: " + "; ".join(iocs)
    return f"**Combined batch:** {line}\n\n**IOCs:** " + "; ".join(iocs)


def render_summary(
    lookup_id: str,
    *,
    fmt: str = "md",
    raw_indicators: bool = False,
    extra_ids: list[str] | None = None,
    tlp: str = "CLEAR",
) -> str:
    ids = [lookup_id] + [i for i in (extra_ids or []) if i and i != lookup_id]
    # de-dupe, keep order
    seen: set[str] = set()
    ordered: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            ordered.append(i)
    sections = [render_one(i, fmt=fmt, raw_indicators=raw_indicators) for i in ordered]
    sections = [s for s in sections if s]
    sep = "\n\n---\n\n" if fmt == "md" else "\n\n==========\n\n"
    body = sep.join(sections)
    prefix = tlp_prefix(tlp)
    if len(ordered) > 1:
        header = _combined_header(ordered, fmt, raw_indicators)
        body = header + sep + body
    return prefix + "\n\n" + body


def render_one(lookup_id: str, *, fmt: str = "md", raw_indicators: bool = False) -> str:
    bundle = lookup_bundle(lookup_id)
    if not bundle:
        return ""
    lu = bundle["lookup"]
    ind = bundle["indicator"]
    registry = get_registry()
    results = []
    specs = {}
    for row in bundle["results"]:
        spec = registry.get(row["provider"])
        name = spec.name if spec else row["provider"]
        if spec:
            specs[spec.id] = spec
        res = row_to_result(row, name)
        results.append(res)

    child_blocks = []
    for child in bundle["children"]:
        child_blocks.append(render_one(child["id"], fmt=fmt, raw_indicators=raw_indicators))

    roll = compute_rollup(results, specs)
    itype = ind["type"]
    value = ind["value"]
    ioc = _display_ioc(value, itype, raw_indicators)
    when = _dt(lu["started_at"])

    flags = list(roll.context_flags)
    for res in results:
        for t in res.tags:
            if t in {"known-benign-infrastructure", "internet-scanner", "allowlisted", "popular", "disposable"}:
                if t not in flags:
                    flags.append(t.replace("-", " "))
    if roll.consensus:
        flags.append("agreement: " + "; ".join(roll.consensus))

    disagree = "Sources disagree (malicious and benign co-occur)." if roll.disagreement else "Sources do not disagree."
    rollup_line = (
        f"{roll.malicious} malicious, {roll.suspicious} suspicious, "
        f"{roll.unknown} unknown, {roll.benign} benign. {disagree}"
    )
    context_line = "; ".join(flags) if flags else "none"

    source_rows = []
    not_checked = []
    finding_links = []
    key_facts: list[str] = []
    related_bits: list[str] = []

    for res in results:
        spec = specs.get(res.provider)
        mode = spec.mode if spec else "api"
        if mode == "link_only" or res.status in {
            ResultStatus.SKIPPED,
            ResultStatus.NO_KEY,
            ResultStatus.RATE_LIMITED,
            ResultStatus.QUEUED,
        }:
            reason = res.skip_reason or res.status.value
            not_checked.append(f"{res.provider_name} ({reason.replace('_', ' ')})")
            continue
        verdict = res.verdict.value if res.verdict else res.status.value
        detail = res.summary
        age = _age(res.queried_at.isoformat() if res.queried_at else None)
        if res.cached and age:
            detail = f"{detail} ({age})"
        source_rows.append((res.provider_name, verdict, detail))
        if res.status == ResultStatus.OK and res.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN}:
            if res.open_source_url:
                finding_links.append(res.open_source_url)
        elif res.status == ResultStatus.OK and res.verdict in {Verdict.UNKNOWN, Verdict.INFO}:
            if res.facts and res.open_source_url:
                finding_links.append(res.open_source_url)
        for f in res.facts:
            if f.label.lower() in {
                "asn",
                "org",
                "isp",
                "country",
                "registrar",
                "family",
                "netblock",
                "open ports",
                "malware",
                "confidence",
            }:
                key_facts.append(f"{f.label}: {f.value}")
        for rel in res.related[:4]:
            related_bits.append(
                f"{rel.relation.replace('_', ' ')} {_display_ioc(rel.value, rel.type.value, raw_indicators)}"
            )

    note = lu["note"] if "note" in lu.keys() else None

    if fmt == "text":
        lines = [
            f"IOC: {ioc} ({itype}), investigated {when}",
            f"Rollup: {rollup_line}",
            f"Context: {context_line}.",
            "",
        ]
        for name, verdict, detail in source_rows:
            lines.append(f"- {name}: {verdict} — {detail}")
        if key_facts:
            lines.append("")
            lines.append("Key facts: " + "; ".join(list(dict.fromkeys(key_facts))[:8]))
        if not_checked:
            lines.append("Not checked / no data: " + ", ".join(not_checked) + ".")
        if related_bits:
            lines.append("Related: " + "; ".join(list(dict.fromkeys(related_bits))[:8]) + ".")
        if finding_links:
            lines.append("Links (sources with findings): " + " ".join(finding_links))
        if note:
            lines.append(f"Analyst note: {note}")
        body = "\n".join(lines)
        if child_blocks:
            body += "\n\nHost lookup:\n" + "\n\n".join(child_blocks)
        return body

    lines = [
        f"**IOC:** {ioc} ({itype}), investigated {when}",
        f"**Rollup:** {rollup_line}",
        f"**Context:** {context_line}.",
        "",
        "| Source | Verdict | Detail |",
        "|---|---|---|",
    ]
    for name, verdict, detail in source_rows:
        detail_esc = detail.replace("|", "\\|")
        lines.append(f"| {name} | {verdict} | {detail_esc} |")
    if key_facts:
        uniq = list(dict.fromkeys(key_facts))[:8]
        lines.append("")
        lines.append("**Key facts:** " + "; ".join(uniq) + ".")
    if not_checked:
        lines.append(f"**Not checked / no data:** {', '.join(not_checked)}.")
    if related_bits:
        uniq = list(dict.fromkeys(related_bits))[:8]
        lines.append("**Related:** " + "; ".join(uniq) + ".")
    if finding_links:
        lines.append("**Links (sources with findings):** " + " ".join(finding_links))
    if note:
        lines.append(f"**Analyst note:** {note}")
    body = "\n".join(lines)
    if child_blocks:
        body += "\n\n### Host lookup\n\n" + "\n\n".join(child_blocks)
    return body
