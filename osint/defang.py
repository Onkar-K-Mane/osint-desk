"""Refang inbound IOCs and defang them for safe display / copy."""

from __future__ import annotations

import re

_HXXP = re.compile(r"\bhxxps?(://)", re.I)
_FXP = re.compile(r"\bfxp(s?://)", re.I)
_DOT = re.compile(r"\[\.\]|\(\.\)|{\.}|\[dot\]|\(dot\)|{dot}", re.I)
_COLON = re.compile(r"\[:\]|\(:\)|{:}")
_AT = re.compile(r"\[@\]|\(@\)|{@}|\[at\]|\(at\)|{at}", re.I)
_SLASH = re.compile(r"\[/\]|\(/\)")


def refang(text: str) -> str:
    """Undo common analyst defanging. Original string is kept by the caller."""
    if not text:
        return text
    out = text
    out = _HXXP.sub(lambda m: ("https://" if m.group(0).lower().startswith("hxxps") else "http://"), out)
    out = re.sub(r"\bhxxp\b", "http", out, flags=re.I)
    out = re.sub(r"\bhxxps\b", "https", out, flags=re.I)
    out = _FXP.sub(r"ftp\1", out)
    out = _DOT.sub(".", out)
    out = _COLON.sub(":", out)
    out = _AT.sub("@", out)
    out = _SLASH.sub("/", out)
    return out


def defang(value: str) -> str:
    """Display-safe form: dots, @, and : inside host/url/email become bracketed."""
    if not value:
        return value
    out = value
    out = out.replace("://", "[://]")
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    # Restore scheme separator after the :// defang so it stays readable
    out = out.replace("[://]", "[://]")
    return out


def defang_url_scheme(value: str) -> str:
    """hxxp-style defang used in summaries."""
    if not value:
        return value
    out = value
    if out.lower().startswith("https://"):
        out = "hxxps://" + out[8:]
    elif out.lower().startswith("http://"):
        out = "hxxp://" + out[7:]
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out
