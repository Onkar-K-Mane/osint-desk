from datetime import datetime, timezone

from osint.db import connect, init_db
from osint.rate_limit import RateLimiter
from osint.registry import SourceSpec
from osint.models import IndicatorType


def _spec(**limits):
    return SourceSpec(
        id="t",
        name="T",
        types={IndicatorType.IP},
        mode="api",
        limits=limits,
        reserve_fraction=0.10,
    )


def test_windows_and_restart(tmp_path):
    db = tmp_path / "q.sqlite3"
    conn = connect(db)
    init_db(conn)
    lim = RateLimiter(conn)
    spec = _spec(per_day=10)
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    allowed, reason, snap = lim.check(spec, now=now)
    assert allowed
    for _ in range(9):
        lim.consume(spec, now=now)
    allowed, reason, snap = lim.check(spec, now=now)
    # 9/10 used, reserve 10% means cap=9, so 9 >= 9 reserved
    assert reason == "quota_reserved"
    allowed, reason, _ = lim.check(spec, force=True, now=now)
    assert allowed
    lim.consume(spec, now=now)
    allowed, reason, _ = lim.check(spec, force=True, now=now)
    assert reason == "rate_limited"

    # restart: new limiter, same db
    lim2 = RateLimiter(conn)
    allowed, reason, snap = lim2.check(spec, now=now)
    assert reason == "rate_limited"
    assert snap.windows["day"]["used"] == 10
