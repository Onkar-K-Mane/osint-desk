"""TTL and window parsing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.I)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(spec: str | int | float | None, default: timedelta | None = None) -> timedelta:
    if spec is None:
        return default or timedelta(hours=6)
    if isinstance(spec, (int, float)):
        return timedelta(seconds=float(spec))
    m = _RE.match(str(spec))
    if not m:
        return default or timedelta(hours=6)
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "w":
        return timedelta(days=7 * n)
    return timedelta(**{_UNITS[unit]: n})


def window_start(now: datetime, window_type: str) -> datetime:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    if window_type == "minute":
        return now.replace(second=0, microsecond=0)
    if window_type == "hour":
        return now.replace(minute=0, second=0, microsecond=0)
    if window_type == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_type == "week":
        monday = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return monday - timedelta(days=monday.weekday())
    return now.replace(second=0, microsecond=0)


def window_end(start: datetime, window_type: str) -> datetime:
    if window_type == "minute":
        return start + timedelta(minutes=1)
    if window_type == "hour":
        return start + timedelta(hours=1)
    if window_type == "day":
        return start + timedelta(days=1)
    if window_type == "week":
        return start + timedelta(weeks=1)
    return start + timedelta(minutes=1)
