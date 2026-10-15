"""Load sources.yaml and bind provider implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from osint.config import SOURCES_PATH, has_key
from osint.models import IndicatorType, ProviderMode


@dataclass
class VerdictConfig:
    style: str = "reputation"  # reputation | allowlist | classification | informational
    malicious_at: float | None = None
    suspicious_at: float | None = None


@dataclass
class TtlConfig:
    default: str = "6h"
    not_found: str = "1h"
    malicious: str | None = None


@dataclass
class SourceSpec:
    id: str
    name: str
    types: set[IndicatorType]
    mode: ProviderMode
    key_env: str | None = None
    limits: dict[str, int] = field(default_factory=dict)
    auto_query: bool = True
    reserve_fraction: float = 0.10
    ttl: TtlConfig = field(default_factory=TtlConfig)
    deeplink: dict[str, str] = field(default_factory=dict)
    verdict: VerdictConfig = field(default_factory=VerdictConfig)
    tos_note: str = ""
    timeout_s: float = 15.0
    enabled: bool = True
    tier: str = "reputation"  # reputation | sandbox | facts | identity | link

    def supports(self, t: IndicatorType) -> bool:
        return t in self.types

    def key_present(self) -> bool:
        return has_key(self.key_env)


class Registry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or SOURCES_PATH
        self.sources: dict[str, SourceSpec] = {}
        self.load()

    def load(self) -> None:
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or []
        self.sources = {}
        for item in raw:
            types = {IndicatorType(t) for t in item.get("types", [])}
            ttl_raw = item.get("ttl") or {}
            if isinstance(ttl_raw, str):
                ttl = TtlConfig(default=ttl_raw)
            else:
                ttl = TtlConfig(
                    default=str(ttl_raw.get("default", "6h")),
                    not_found=str(ttl_raw.get("not_found", "1h")),
                    malicious=ttl_raw.get("malicious"),
                )
            vraw = item.get("verdict") or {}
            verdict = VerdictConfig(
                style=str(vraw.get("style", "reputation")),
                malicious_at=_as_float(vraw.get("malicious_at")),
                suspicious_at=_as_float(vraw.get("suspicious_at")),
            )
            mode = item.get("mode", "api")
            spec = SourceSpec(
                id=item["id"],
                name=item.get("name", item["id"]),
                types=types,
                mode=mode,
                key_env=item.get("key_env"),
                limits={k: int(v) for k, v in (item.get("limits") or {}).items()},
                auto_query=bool(item.get("auto_query", True)),
                reserve_fraction=float(item.get("reserve_fraction", 0.10)),
                ttl=ttl,
                deeplink=item.get("deeplink") or {},
                verdict=verdict,
                tos_note=item.get("tos_note") or "",
                timeout_s=float(item.get("timeout_s", 15)),
                enabled=bool(item.get("enabled", True)),
                tier=_infer_tier(item, mode, verdict.style),
            )
            self.sources[spec.id] = spec

    def for_type(self, t: IndicatorType, *, include_disabled: bool = False) -> list[SourceSpec]:
        out = []
        for s in self.sources.values():
            if t not in s.types:
                continue
            if not include_disabled and not s.enabled:
                continue
            out.append(s)
        order = {"reputation": 0, "sandbox": 1, "facts": 2, "identity": 3, "link": 4}
        out.sort(key=lambda s: (order.get(s.tier, 9), s.name.lower()))
        return out

    def get(self, sid: str) -> SourceSpec | None:
        return self.sources.get(sid)


def _infer_tier(item: dict, mode: str, style: str) -> str:
    if item.get("tier"):
        return str(item["tier"])
    if mode == "link_only":
        return "link"
    sid = item.get("id", "")
    if sid in {"hybrid_analysis", "triage"}:
        return "sandbox"
    if sid in {"hunter", "hibp", "dmarc_spf"}:
        return "identity"
    if style in {"informational", "allowlist"}:
        return "facts"
    return "reputation"


def _as_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    return float(v)


_REGISTRY: Registry | None = None


def get_registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = Registry()
    return _REGISTRY
