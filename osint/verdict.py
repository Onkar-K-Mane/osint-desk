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
