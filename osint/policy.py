"""Outbound policy: never send private/internal indicators off-box."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

from osint.config import PACKAGE_DATA
from osint.models import Indicator, IndicatorType, PolicyDecision
from osint.psl import default_psl

_INTERNAL_SUFFIXES = {
    "local",
    "internal",
    "lan",
    "corp",
    "home",
    "intranet",
    "localhost",
    "localdomain",
    "test",
    "invalid",
}

# RFC 2606 / docs — treated as internal-looking, no external queries
_DOC_DOMAINS = {"example.com", "example.net", "example.org", "example.edu"}


@lru_cache(maxsize=1)
def top_domains() -> set[str]:
    path = PACKAGE_DATA / "top_domains.txt"
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


@lru_cache(maxsize=1)
def disposable_domains() -> set[str]:
    path = PACKAGE_DATA / "disposable_email_domains.txt"
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def _ip_blocked_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    # is_reserved covers IETF reserved; also catch documentation ranges via is_global
    if hasattr(ip, "is_global") and not ip.is_global:
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return None  # already handled
        return "non-global address"
    return None


def _host_internal(host: str) -> str | None:
    host = host.strip(".").lower()
    if not host:
        return "empty host"
    if "." not in host:
        return "single-label hostname"
    suffix = host.rsplit(".", 1)[-1]
    if suffix in _INTERNAL_SUFFIXES:
        return f"internal suffix .{suffix}"
    # RFC 6762 .local already covered
    if host in _DOC_DOMAINS or any(host.endswith("." + d) for d in _DOC_DOMAINS):
        return "documentation domain"
    return None


def evaluate(ind: Indicator) -> PolicyDecision:
    if ind.type == IndicatorType.IP:
        ip = ipaddress.ip_address(ind.value)
        reason = _ip_blocked_reason(ip)
        if reason:
            return PolicyDecision(
                allow_external=False,
                reason=reason,
                local_summary=f"External queries blocked: {reason}. Nothing left this machine.",
                tags=["local-only", "policy-block"],
            )
        return PolicyDecision(allow_external=True)

    host = None
    if ind.type == IndicatorType.DOMAIN:
        host = ind.value
    elif ind.type == IndicatorType.URL:
        host = ind.url_host
        if ind.url_host_type == IndicatorType.IP and host:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                ip = None
            if ip is not None:
                reason = _ip_blocked_reason(ip)
                if reason:
                    return PolicyDecision(
                        allow_external=False,
                        reason=reason,
                        local_summary=f"URL host is {reason}; external queries blocked.",
                        tags=["local-only", "policy-block"],
                    )
    elif ind.type == IndicatorType.EMAIL:
        host = ind.email_domain

    if host:
        internal = _host_internal(host)
        if internal:
            return PolicyDecision(
                allow_external=False,
                reason=internal,
                local_summary=f"External queries blocked: {internal}.",
                tags=["local-only", "policy-block"],
            )
        # Allowlisted / top-ranked → lightweight
        registrable = default_psl().registrable_domain(host) or host
        if host in top_domains() or registrable in top_domains():
            return PolicyDecision(
                allow_external=True,
                lightweight=True,
                reason="top-ranked / allowlisted infrastructure",
                local_summary=(
                    f"{registrable} is on the local popularity allowlist. "
                    "Running a lightweight lookup. Use Full lookup to query every API."
                ),
                tags=["allowlisted", "lightweight", "popular"],
            )

    if ind.type == IndicatorType.EMAIL and ind.email_domain:
        if ind.email_domain in disposable_domains():
            return PolicyDecision(
                allow_external=True,
                lightweight=False,
                reason=None,
                tags=["disposable-email-domain"],
            )

    return PolicyDecision(allow_external=True)
