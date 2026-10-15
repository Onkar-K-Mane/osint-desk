"""Shared dataclasses for indicators, results, and events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class IndicatorType(str, Enum):
    URL = "url"
    EMAIL = "email"
    IP = "ip"
    HASH = "hash"
    DOMAIN = "domain"


class LookupTrigger(str, Enum):
    MANUAL = "manual"
    PIVOT = "pivot"
    REFRESH = "refresh"
    AUTO_CHILD = "auto_child"
    BULK = "bulk"


class ResultStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    NO_KEY = "no_key"
    SKIPPED = "skipped"
    QUEUED = "queued"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    INFO = "info"
    UNKNOWN = "unknown"


class AnalystVerdict(str, Enum):
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    MONITORING = "monitoring"


ProviderMode = Literal["api", "local", "link_only"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Indicator:
    type: IndicatorType
    value: str  # normalized
    original: str
    hash_algo: str | None = None  # md5 / sha1 / sha256 / sha512
    url_host: str | None = None
    url_host_type: IndicatorType | None = None  # domain or ip
    email_domain: str | None = None
    origin: str = "regex"  # regex | ai

    @property
    def key(self) -> tuple[str, str]:
        return (self.type.value, self.value)


@dataclass
class Related:
    type: IndicatorType
    value: str
    relation: str


@dataclass
class Fact:
    label: str
    value: str


@dataclass
class RawResponse:
    status_code: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""
    error: str | None = None

    def text(self) -> str:
        if not self.body:
            return ""
        return self.body.decode("utf-8", errors="replace")


@dataclass
class ParsedResult:
    summary: str = ""
    facts: list[Fact] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related: list[Related] = field(default_factory=list)
    status: ResultStatus = ResultStatus.OK
    score: float | None = None
    classification: str | None = None
    allowlist_hit: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResult:
    provider: str
    provider_name: str
    status: ResultStatus
    skip_reason: str | None = None
    verdict: Verdict | None = None
    summary: str = ""
    facts: list[Fact] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related: list[Related] = field(default_factory=list)
    open_source_url: str | None = None
    queried_at: datetime = field(default_factory=utcnow)
    expires_at: datetime | None = None
    quota: dict[str, Any] | None = None
    raw: bytes | None = None
    parser_version: int = 1
    cached: bool = False
    result_id: int | None = None
    style: str = "reputation"
    tier: str = "reputation"

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "provider": self.provider,
            "provider_name": self.provider_name,
            "status": self.status.value,
            "skip_reason": self.skip_reason,
            "verdict": self.verdict.value if self.verdict else None,
            "summary": self.summary,
            "facts": [{"label": f.label, "value": f.value} for f in self.facts],
            "tags": self.tags,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "related": [
                {"type": r.type.value, "value": r.value, "relation": r.relation}
                for r in self.related
            ],
            "open_source_url": self.open_source_url,
            "queried_at": iso(self.queried_at),
            "expires_at": iso(self.expires_at),
            "cached": self.cached,
            "quota": self.quota,
            "style": self.style,
            "tier": self.tier,
            "has_raw": bool(self.raw) or bool(self.result_id),
        }


@dataclass
class Rollup:
    malicious: int = 0
    suspicious: int = 0
    benign: int = 0
    info: int = 0
    unknown: int = 0
    disagreement: bool = False
    context_flags: list[str] = field(default_factory=list)
    coverage: str = ""
    answered: int = 0
    total_api: int = 0
    rate_limited: int = 0
    link_only: int = 0
    skipped: int = 0
    errors: int = 0
    no_key: int = 0
    not_found: int = 0
    consensus: list[str] = field(default_factory=list)


@dataclass
class PolicyDecision:
    allow_external: bool = True
    lightweight: bool = False
    reason: str | None = None
    local_summary: str = ""
    tags: list[str] = field(default_factory=list)
