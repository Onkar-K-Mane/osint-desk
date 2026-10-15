"""Verdict mapping is separate from parse, driven by sources.yaml thresholds."""

from __future__ import annotations

from osint.models import ParsedResult, ResultStatus, Verdict
from osint.registry import SourceSpec, VerdictConfig


def map_verdict(spec: SourceSpec, parsed: ParsedResult, status: ResultStatus) -> Verdict | None:
    if status != ResultStatus.OK:
        return None
    cfg = spec.verdict or VerdictConfig()
    style = cfg.style or "reputation"

    if style == "informational":
        return Verdict.INFO

    if style == "allowlist":
        return Verdict.BENIGN if parsed.allowlist_hit else Verdict.UNKNOWN

    if style == "classification":
        raw = (parsed.classification or "").lower()
        if raw in {"malicious", "suspicious", "benign", "unknown"}:
            return Verdict(raw)
        if raw in {"riot", "benign_service", "ok"}:
            return Verdict.BENIGN
        if raw in {"noise", "scanner"}:
            return Verdict.UNKNOWN
        return Verdict.UNKNOWN

    # reputation: only bad or no opinion. "no reports" is unknown, never benign.
    score = parsed.score
    if score is None:
        return Verdict.UNKNOWN
    if cfg.malicious_at is not None and score >= cfg.malicious_at:
        return Verdict.MALICIOUS
    if cfg.suspicious_at is not None and score >= cfg.suspicious_at:
        return Verdict.SUSPICIOUS
    return Verdict.UNKNOWN


def rollup_from_results(results: list) -> "object":
    from osint.models import Rollup, ResultStatus, Verdict

    r = Rollup()
    r.total_api = 0
    for item in results:
        st = item.status if isinstance(item.status, ResultStatus) else ResultStatus(item.status)
        if item.provider_name and getattr(item, "mode", None) == "link_only":
            r.link_only += 1
            continue
        if st == ResultStatus.OK:
            r.answered += 1
            v = item.verdict
            if v == Verdict.MALICIOUS:
                r.malicious += 1
            elif v == Verdict.SUSPICIOUS:
                r.suspicious += 1
            elif v == Verdict.BENIGN:
                r.benign += 1
            else:
                r.unknown += 1
        elif st == ResultStatus.NOT_FOUND:
            r.not_found += 1
            r.answered += 1
            r.unknown += 1
        elif st == ResultStatus.RATE_LIMITED:
            r.rate_limited += 1
        elif st == ResultStatus.NO_KEY:
            r.no_key += 1
        elif st == ResultStatus.SKIPPED:
            r.skipped += 1
        elif st == ResultStatus.ERROR:
            r.errors += 1
        r.total_api += 1
    r.disagreement = r.malicious > 0 and r.benign > 0
    parts = []
    answered = r.malicious + r.suspicious + r.benign + r.unknown
    # coverage uses original result list length
    n = len(results)
    parts.append(f"{r.answered} of {n} sources answered")
    if r.rate_limited:
        parts.append(f"{r.rate_limited} rate-limited")
    if r.no_key:
        parts.append(f"{r.no_key} missing key")
    if r.skipped:
        parts.append(f"{r.skipped} skipped")
    if r.errors:
        parts.append(f"{r.errors} error")
    r.coverage = ", ".join(parts) + "."
    return r
