"""Public Suffix List matcher (no network)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from osint.config import PACKAGE_DATA

_PSL_PATH = PACKAGE_DATA / "public_suffix_list.dat"


class PublicSuffixList:
    def __init__(self, path: Path | None = None) -> None:
        self.rules: set[str] = set()
        self.exceptions: set[str] = set()
        self.wildcards: set[str] = set()  # suffix after "*."
        self._load(path or _PSL_PATH)

    def _load(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exceptions.add(line[1:].lstrip(".").lower())
                continue
            if line.startswith("*."):
                self.wildcards.add(line[2:].lstrip(".").lower())
                continue
            self.rules.add(line.lstrip(".").lower())

    def _labels(self, host: str) -> list[str]:
        host = host.strip(".").lower()
        if not host:
            return []
        return host.split(".")

    def public_suffix(self, host: str) -> str | None:
        labels = self._labels(host)
        if not labels:
            return None
        # Walk from the right, find the matching rule of greatest length.
        # PSL algorithm: find prevailing rule among exception > wildcard > rule.
        n = len(labels)
        exception_at = None
        wildcard_at = None
        rule_at = None
        for i in range(n):
            candidate = ".".join(labels[i:])
            parent = ".".join(labels[i + 1 :]) if i + 1 < n else ""
            if candidate in self.exceptions:
                exception_at = i
            if parent in self.wildcards:
                wildcard_at = i
            if candidate in self.rules:
                rule_at = i
        if exception_at is not None:
            # exception: public suffix is everything after the leftmost label of the exception
            return ".".join(labels[exception_at + 1 :]) if exception_at + 1 < n else ""
        if wildcard_at is not None:
            return ".".join(labels[wildcard_at:])
        if rule_at is not None:
            return ".".join(labels[rule_at:])
        # default: last label
        return labels[-1]

    def registrable_domain(self, host: str) -> str | None:
        labels = self._labels(host)
        if len(labels) < 2:
            return None
        suffix = self.public_suffix(host)
        if suffix is None:
            return None
        suffix_labels = suffix.split(".") if suffix else []
        leftover = len(labels) - len(suffix_labels)
        if leftover < 1:
            return None  # host is itself a public suffix
        return ".".join(labels[-(len(suffix_labels) + 1) :])

    def is_valid_hostname_domain(self, host: str) -> bool:
        """True if host has a label to the left of a known public suffix."""
        if not host or len(host) > 253:
            return False
        labels = self._labels(host)
        if len(labels) < 2:
            return False
        for lab in labels:
            if not lab or len(lab) > 63:
                return False
            if lab.startswith("-") or lab.endswith("-"):
                return False
            if not all(c.isalnum() or c == "-" for c in lab):
                return False
        return self.registrable_domain(host) is not None


@lru_cache(maxsize=1)
def default_psl() -> PublicSuffixList:
    return PublicSuffixList()
