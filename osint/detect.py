"""Extract, refang, classify, and normalize indicators."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from osint.defang import refang
from osint.models import Indicator, IndicatorType
from osint.psl import default_psl

_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b")
_EMAIL_RE = re.compile(
    r"\b([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})\b",
    re.I,
)
# IPv4 including after refang
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# IPv6: compressed forms. Keep conservative to avoid eating hashes.
_IPV6_RE = re.compile(
    r"\b(?:(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"
    r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"
    r"|:(?::[A-Fa-f0-9]{1,4}){1,7}"
    r"|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4})\b"
)
_SCHEME_RE = re.compile(r"^(https?|ftp|hxxps?)://", re.I)
# host + path (no scheme): example.com/a or 1.2.3.4/foo
_HOST_PATH_RE = re.compile(
    r"\b((?:[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+|\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?/[^\s,;<>\"']+)"
)
_URL_RE = re.compile(
    r"\b((?:https?|ftp)://[^\s,;<>\"']+)",
    re.I,
)
_DOMAIN_RE = re.compile(
    r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})\b"
)

_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# Labels that must not be treated as "internal" just because they are short
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
    "example",
}


def _idna_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _looks_like_hash(value: str) -> bool:
    v = value.strip()
    return bool(_HASH_RE.fullmatch(v)) and all(c in "0123456789abcdefABCDEF" for c in v)


def canonicalize_url(url: str) -> tuple[str, str | None, IndicatorType | None]:
    """Lowercase scheme/host, punycode, drop empty path default, keep query/fragment."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or ""
    ip = _parse_ip(host)
    host_type: IndicatorType | None = None
    if ip is not None:
        host_norm = str(ip)
        host_type = IndicatorType.IP
    elif host:
        host_norm = _idna_host(host)
        host_type = IndicatorType.DOMAIN
    else:
        host_norm = host
    netloc = host_norm
    if parts.port:
        default = (scheme == "http" and parts.port == 80) or (
            scheme == "https" and parts.port == 443
        )
        if not default:
            netloc = f"{host_norm}:{parts.port}"
    if ip is not None and ip.version == 6 and parts.port and not (
        (scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443)
    ):
        netloc = f"[{host_norm}]:{parts.port}"
    elif ip is not None and ip.version == 6:
        netloc = f"[{host_norm}]"
    path = parts.path or ""
    # Keep original path; collapse empty
    query = parts.query
    fragment = parts.fragment
    canonical = urlunsplit((scheme, netloc, path, query, fragment))
    return canonical, host_norm or None, host_type


def classify_one(raw: str) -> Indicator | None:
    """Classify a single (already-refanged) value. Order: URL, email, IP, hash, domain."""
    original = raw.strip()
    if not original or len(original) > 2048:
        return None
    value = original.strip(".,;\"'<>()[]{} \t")
    if not value:
        return None

    # 1. URL — scheme, or host followed by a path
    if _SCHEME_RE.match(value) or (
        "/" in value
        and not value.startswith("/")
        and "@" not in value.split("/")[0]
        and _HOST_PATH_RE.match(value)
    ):
        url = value
        if not _SCHEME_RE.match(url):
            url = "http://" + url
        try:
            canonical, host, host_type = canonicalize_url(url)
        except Exception:
            canonical, host, host_type = url, None, None
        parts = urlsplit(canonical)
        if parts.hostname:
            return Indicator(
                type=IndicatorType.URL,
                value=canonical,
                original=original,
                url_host=host,
                url_host_type=host_type,
            )

    # 2. Email
    if value.count("@") == 1:
        local, _, domain = value.partition("@")
        if local and domain and "." in domain:
            try:
                domain_norm = _idna_host(domain)
            except Exception:
                domain_norm = domain.lower()
            if default_psl().is_valid_hostname_domain(domain_norm) or _parse_ip(domain):
                return Indicator(
                    type=IndicatorType.EMAIL,
                    value=f"{local.lower()}@{domain_norm}",
                    original=original,
                    email_domain=domain_norm,
                )

    # 3. IP
    ip = _parse_ip(value)
    if ip is not None:
        return Indicator(type=IndicatorType.IP, value=str(ip), original=original)

    # 4. Hash
    compact = value.lower().replace(" ", "")
    if _looks_like_hash(compact):
        return Indicator(
            type=IndicatorType.HASH,
            value=compact.lower(),
            original=original,
            hash_algo=_HASH_LEN[len(compact)],
        )

    # 5. Domain
    host = value.rstrip(".").lower()
    if host.startswith("www."):
        # still a domain
        pass
    try:
        host_idna = _idna_host(host)
    except Exception:
        host_idna = host
    if default_psl().is_valid_hostname_domain(host_idna):
        return Indicator(type=IndicatorType.DOMAIN, value=host_idna, original=original)

    return None


def _span_occupied(occupied: list[tuple[int, int]], start: int, end: int) -> bool:
    for a, b in occupied:
        if start < b and end > a:
            return True
    return False


def extract_indicators(text: str) -> list[Indicator]:
    """Extract unique indicators from a single value or an alert blob."""
    if not text or not text.strip():
        return []
    original_text = text
    cleaned = refang(text)

    # Fast path: whole input is one IOC
    stripped = cleaned.strip()
    if "\n" not in stripped and len(stripped) <= 512:
        one = classify_one(stripped)
        if one:
            one.original = original_text.strip()
            return [one]

    found: list[Indicator] = []
    occupied: list[tuple[int, int]] = []
    seen: set[tuple[str, str]] = set()

    def add(ind: Indicator, start: int, end: int) -> None:
        if _span_occupied(occupied, start, end):
            return
        if ind.key in seen:
            occupied.append((start, end))
            return
        seen.add(ind.key)
        occupied.append((start, end))
        found.append(ind)

    for m in _URL_RE.finditer(cleaned):
        ind = classify_one(m.group(1))
        if ind and ind.type == IndicatorType.URL:
            add(ind, m.start(), m.end())

    for m in _HOST_PATH_RE.finditer(cleaned):
        ind = classify_one(m.group(1))
        if ind and ind.type == IndicatorType.URL:
            add(ind, m.start(), m.end())

    for m in _EMAIL_RE.finditer(cleaned):
        ind = classify_one(m.group(1))
        if ind and ind.type == IndicatorType.EMAIL:
            add(ind, m.start(), m.end())

    for m in _IPV6_RE.finditer(cleaned):
        ind = classify_one(m.group(0))
        if ind and ind.type == IndicatorType.IP:
            add(ind, m.start(), m.end())

    for m in _IPV4_RE.finditer(cleaned):
        ind = classify_one(m.group(0))
        if ind and ind.type == IndicatorType.IP:
            add(ind, m.start(), m.end())

    for m in _HASH_RE.finditer(cleaned):
        ind = classify_one(m.group(1))
        if ind and ind.type == IndicatorType.HASH:
            add(ind, m.start(), m.end())

    for m in _DOMAIN_RE.finditer(cleaned):
        ind = classify_one(m.group(1))
        if ind and ind.type == IndicatorType.DOMAIN:
            add(ind, m.start(), m.end())

    return found


def url_sha256(url: str) -> str:
    """VirusTotal GUI URL identifier: SHA-256 of the canonical URL bytes."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()
