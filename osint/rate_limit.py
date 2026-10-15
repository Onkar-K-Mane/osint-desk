"""Persisted token-bucket / window counters. Restart-safe."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from osint.db import get_conn
from osint.models import iso, utcnow
from osint.registry import SourceSpec
from osint.ttl import window_end, window_start

SkipKind = Literal["quota_reserved", "rate_limited", "circuit_open"] | None


@dataclass
class QuotaSnapshot:
    windows: dict[str, dict]  # type -> {used, limit, reset}
    reserved: bool = False
    blocked: bool = False
    reason: str | None = None


def _limit_key_to_window(key: str) -> str | None:
    # per_minute / per_day / per_week / per_hour
    mapping = {
        "per_minute": "minute",
        "per_min": "minute",
        "per_hour": "hour",
        "per_day": "day",
        "per_week": "week",
    }
    return mapping.get(key)


class RateLimiter:
    def __init__(self, conn: sqlite3.Connection | None = None) -> None:
        self._conn = conn

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn or get_conn()

    def snapshot(self, spec: SourceSpec, now: datetime | None = None) -> QuotaSnapshot:
        now = now or utcnow()
        windows: dict[str, dict] = {}
        reserved = False
        blocked = False
        reason = None
        for key, limit in spec.limits.items():
            wtype = _limit_key_to_window(key)
            if not wtype:
                continue
            start = window_start(now, wtype)
            used = self._count(spec.id, wtype, start)
            reset = window_end(start, wtype)
            windows[wtype] = {
                "used": used,
                "limit": limit,
                "reset": iso(reset),
                "window_start": iso(start),
            }
            cap = int(limit * (1.0 - spec.reserve_fraction))
            if used >= limit:
                blocked = True
                reason = f"{wtype} limit reached ({used}/{limit})"
            elif used >= cap:
                reserved = True
                reason = f"{wtype} reserve ({used}/{limit}, cap {cap})"
        return QuotaSnapshot(windows=windows, reserved=reserved, blocked=blocked, reason=reason)

    def _count(self, provider: str, wtype: str, start: datetime) -> int:
        row = self.conn.execute(
            "SELECT count FROM quota_usage WHERE provider=? AND window_type=? AND window_start=?",
            (provider, wtype, iso(start)),
        ).fetchone()
        return int(row["count"]) if row else 0

    def check(
        self, spec: SourceSpec, *, force: bool = False, now: datetime | None = None
    ) -> tuple[bool, str | None, QuotaSnapshot]:
        """Return (allowed, skip_reason, snapshot)."""
        snap = self.snapshot(spec, now)
        opened = self._circuit_open(spec.id, now or utcnow())
        if opened:
            return False, "circuit_open", snap
        if not spec.limits:
            return True, None, snap
        if snap.blocked:
            return False, "rate_limited", snap
        if snap.reserved and not force:
            return False, "quota_reserved", snap
        return True, None, snap

    def consume(self, spec: SourceSpec, now: datetime | None = None) -> QuotaSnapshot:
        now = now or utcnow()
        for key, _limit in spec.limits.items():
            wtype = _limit_key_to_window(key)
            if not wtype:
                continue
            start = window_start(now, wtype)
            self.conn.execute(
                """
                INSERT INTO quota_usage(provider, window_type, window_start, count)
                VALUES (?,?,?,1)
                ON CONFLICT(provider, window_type, window_start)
                DO UPDATE SET count = count + 1
                """,
                (spec.id, wtype, iso(start)),
            )
        self.conn.commit()
        return self.snapshot(spec, now)

    def sync_from_headers(self, spec: SourceSpec, remaining: int | None, limit: int | None) -> None:
        """If a provider reports remaining, align the current day window."""
        if remaining is None or limit is None:
            return
        used = max(0, limit - remaining)
        now = utcnow()
        start = window_start(now, "day")
        self.conn.execute(
            """
            INSERT INTO quota_usage(provider, window_type, window_start, count)
            VALUES (?,?,?,?)
            ON CONFLICT(provider, window_type, window_start)
            DO UPDATE SET count = MAX(count, excluded.count)
            """,
            (spec.id, "day", iso(start), used),
        )
        self.conn.commit()

    def record_failure(self, provider: str, now: datetime | None = None) -> None:
        now = now or utcnow()
        row = self.conn.execute(
            "SELECT fail_count, opened_until FROM circuit_breaker WHERE provider=?",
            (provider,),
        ).fetchone()
        count = int(row["fail_count"]) + 1 if row else 1
        opened_until = None
        if count >= 5:
            from datetime import timedelta

            opened_until = iso(now + timedelta(minutes=10))
            count = 0
        self.conn.execute(
            """
            INSERT INTO circuit_breaker(provider, fail_count, opened_until)
            VALUES (?,?,?)
            ON CONFLICT(provider) DO UPDATE SET fail_count=excluded.fail_count,
              opened_until=excluded.opened_until
            """,
            (provider, count, opened_until),
        )
        self.conn.commit()

    def record_success(self, provider: str) -> None:
        self.conn.execute(
            """
            INSERT INTO circuit_breaker(provider, fail_count, opened_until)
            VALUES (?,0,NULL)
            ON CONFLICT(provider) DO UPDATE SET fail_count=0, opened_until=NULL
            """,
            (provider,),
        )
        self.conn.commit()

    def _circuit_open(self, provider: str, now: datetime) -> bool:
        row = self.conn.execute(
            "SELECT opened_until FROM circuit_breaker WHERE provider=?",
            (provider,),
        ).fetchone()
        if not row or not row["opened_until"]:
            return False
        until = row["opened_until"]
        return until > (iso(now) or "")

    def cooldown(self, provider: str, seconds: int, now: datetime | None = None) -> None:
        now = now or utcnow()
        from datetime import timedelta

        until = iso(now + timedelta(seconds=max(1, seconds)))
        self.conn.execute(
            """
            INSERT INTO circuit_breaker(provider, fail_count, opened_until)
            VALUES (?,0,?)
            ON CONFLICT(provider) DO UPDATE SET opened_until=excluded.opened_until
            """,
            (provider, until),
        )
        self.conn.commit()
