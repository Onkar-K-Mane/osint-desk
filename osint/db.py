"""SQLite schema, FTS5, and persistence helpers."""

from __future__ import annotations

import gzip
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from osint.config import DATA_DIR, DB_PATH, ensure_data_dir
from osint.models import (
    Fact,
    Indicator,
    IndicatorType,
    ProviderResult,
    Related,
    ResultStatus,
    Verdict,
    iso,
    utcnow,
)

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    original TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    lookup_count INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    UNIQUE(type, value)
);

CREATE TABLE IF NOT EXISTS lookups (
    id TEXT PRIMARY KEY,
    indicator_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    trigger TEXT NOT NULL,
    parent_lookup_id TEXT,
    finished_at TEXT,
    note TEXT,
    FOREIGN KEY (indicator_id) REFERENCES indicators(id),
    FOREIGN KEY (parent_lookup_id) REFERENCES lookups(id)
);

CREATE TABLE IF NOT EXISTS provider_results (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    indicator_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    skip_reason TEXT,
    verdict TEXT,
    summary TEXT,
    facts_json TEXT,
    tags_json TEXT,
    first_seen TEXT,
    last_seen TEXT,
    related_json TEXT,
    open_source_url TEXT,
    queried_at TEXT NOT NULL,
    expires_at TEXT,
    parser_version INTEGER NOT NULL DEFAULT 1,
    raw BLOB,
    quota_json TEXT,
    FOREIGN KEY (indicator_id) REFERENCES indicators(id)
);

CREATE INDEX IF NOT EXISTS idx_pr_ind_prov_q
    ON provider_results(indicator_id, provider, queried_at DESC);
CREATE INDEX IF NOT EXISTS idx_pr_queried ON provider_results(queried_at);

CREATE TABLE IF NOT EXISTS lookup_results (
    lookup_id TEXT NOT NULL,
    result_id INTEGER NOT NULL,
    PRIMARY KEY (lookup_id, result_id),
    FOREIGN KEY (lookup_id) REFERENCES lookups(id),
    FOREIGN KEY (result_id) REFERENCES provider_results(id)
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    from_indicator_id INTEGER NOT NULL,
    to_type TEXT NOT NULL,
    to_value TEXT NOT NULL,
    relation TEXT NOT NULL,
    provider TEXT,
    lookup_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (from_indicator_id) REFERENCES indicators(id)
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_indicator_id);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_type, to_value);

CREATE TABLE IF NOT EXISTS quota_usage (
    provider TEXT NOT NULL,
    window_type TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, window_type, window_start)
);

CREATE TABLE IF NOT EXISTS provider_settings (
    provider TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    auto_query INTEGER,
    malicious_at REAL,
    suspicious_at REAL
);

CREATE TABLE IF NOT EXISTS circuit_breaker (
    provider TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    opened_until TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_history USING fts5(
    value,
    tags,
    facts,
    summary,
    raw,
    indicator_id UNINDEXED,
    type UNINDEXED
);

CREATE TABLE IF NOT EXISTS analyst_verdicts (
    id INTEGER PRIMARY KEY,
    indicator_id INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (indicator_id) REFERENCES indicators(id)
);
CREATE INDEX IF NOT EXISTS idx_av_ind ON analyst_verdicts(indicator_id, created_at DESC);

CREATE TABLE IF NOT EXISTS db_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    ensure_data_dir()
    db_path = path or DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = connect()
        _local.conn = conn
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    c = conn or get_conn()
    c.executescript(SCHEMA)
    _migrate(c)
    c.commit()


def _migrate(c: sqlite3.Connection) -> None:
    # Older DBs may lack newer columns/tables; CREATE IF NOT EXISTS already ran.
    cols = {r[1] for r in c.execute("PRAGMA table_info(indicators)").fetchall()}
    if "note" not in cols:
        try:
            c.execute("ALTER TABLE indicators ADD COLUMN note TEXT")
        except sqlite3.OperationalError:
            pass
    # Ensure FTS has summary/raw columns; rebuild if the old 4-col schema is present.
    try:
        info = c.execute("PRAGMA table_info(fts_history)").fetchall()
        names = {r[1] for r in info}
        if info and "summary" not in names:
            rebuild_fts(c)
    except sqlite3.OperationalError:
        rebuild_fts(c)


def compress_raw(data: bytes | str | dict | None) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, dict):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return gzip.compress(payload, compresslevel=6)


def decompress_raw(blob: bytes | None) -> str | None:
    if not blob:
        return None
    try:
        return gzip.decompress(blob).decode("utf-8", errors="replace")
    except OSError:
        return blob.decode("utf-8", errors="replace")


def upsert_indicator(ind: Indicator, conn: sqlite3.Connection | None = None) -> int:
    c = conn or get_conn()
    now = iso(utcnow())
    row = c.execute(
        "SELECT id, lookup_count FROM indicators WHERE type=? AND value=?",
        (ind.type.value, ind.value),
    ).fetchone()
    if row:
        c.execute(
            "UPDATE indicators SET last_seen=?, lookup_count=lookup_count+1 WHERE id=?",
            (now, row["id"]),
        )
        c.commit()
        return int(row["id"])
    cur = c.execute(
        "INSERT INTO indicators(type, value, original, first_seen, last_seen, lookup_count) "
        "VALUES (?,?,?,?,?,1)",
        (ind.type.value, ind.value, ind.original, now, now),
    )
    c.commit()
    iid = int(cur.lastrowid)
    c.execute(
        "INSERT INTO fts_history(value, tags, facts, summary, raw, indicator_id, type) VALUES (?,?,?,?,?,?,?)",
        (ind.value, "", "", "", "", iid, ind.type.value),
    )
    c.commit()
    return iid


def create_lookup(
    lookup_id: str,
    indicator_id: int,
    trigger: str,
    parent_lookup_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> None:
    c = conn or get_conn()
    c.execute(
        "INSERT INTO lookups(id, indicator_id, started_at, trigger, parent_lookup_id) "
        "VALUES (?,?,?,?,?)",
        (lookup_id, indicator_id, iso(utcnow()), trigger, parent_lookup_id),
    )
    c.commit()


def finish_lookup(lookup_id: str, conn: sqlite3.Connection | None = None) -> None:
    c = conn or get_conn()
    c.execute(
        "UPDATE lookups SET finished_at=? WHERE id=?",
        (iso(utcnow()), lookup_id),
    )
    c.commit()


def persist_result(
    indicator_id: int,
    lookup_id: str,
    result: ProviderResult,
    conn: sqlite3.Connection | None = None,
) -> int:
    c = conn or get_conn()
    cur = c.execute(
        """
        INSERT INTO provider_results(
            provider, indicator_id, status, skip_reason, verdict, summary,
            facts_json, tags_json, first_seen, last_seen, related_json,
            open_source_url, queried_at, expires_at, parser_version, raw, quota_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            result.provider,
            indicator_id,
            result.status.value,
            result.skip_reason,
            result.verdict.value if result.verdict else None,
            result.summary,
            json.dumps([{"label": f.label, "value": f.value} for f in result.facts]),
            json.dumps(result.tags),
            iso(result.first_seen),
            iso(result.last_seen),
            json.dumps(
                [
                    {"type": r.type.value, "value": r.value, "relation": r.relation}
                    for r in result.related
                ]
            ),
            result.open_source_url,
            iso(result.queried_at) or iso(utcnow()),
            iso(result.expires_at),
            result.parser_version,
            result.raw,
            json.dumps(result.quota) if result.quota else None,
        ),
    )
    rid = int(cur.lastrowid)
    c.execute(
        "INSERT OR IGNORE INTO lookup_results(lookup_id, result_id) VALUES (?,?)",
        (lookup_id, rid),
    )
    for rel in result.related:
        c.execute(
            "INSERT INTO edges(from_indicator_id, to_type, to_value, relation, provider, lookup_id, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                indicator_id,
                rel.type.value,
                rel.value,
                rel.relation,
                result.provider,
                lookup_id,
                iso(utcnow()),
            ),
        )
    tags = " ".join(result.tags)
    facts = " ".join(f"{f.label} {f.value}" for f in result.facts)
    raw_txt = ""
    if result.raw:
        raw_txt = (decompress_raw(result.raw) or "")[:8000]
    try:
        c.execute(
            "INSERT INTO fts_history(value, tags, facts, summary, raw, indicator_id, type) VALUES (?,?,?,?,?,?,?)",
            ("", tags, facts, result.summary or "", raw_txt, indicator_id, ""),
        )
    except sqlite3.OperationalError:
        c.execute(
            "INSERT INTO fts_history(value, tags, facts, indicator_id, type) VALUES (?,?,?,?,?)",
            ("", tags, facts, indicator_id, ""),
        )
    c.commit()
    result.result_id = rid
    return rid


def link_cached_result(
    lookup_id: str, result_id: int, conn: sqlite3.Connection | None = None
) -> None:
    c = conn or get_conn()
    c.execute(
        "INSERT OR IGNORE INTO lookup_results(lookup_id, result_id) VALUES (?,?)",
        (lookup_id, result_id),
    )
    c.commit()


def latest_cached(
    indicator_id: int, provider: str, now: datetime | None = None, conn: sqlite3.Connection | None = None
) -> sqlite3.Row | None:
    """Return a cached result if it is still within the 60-minute reuse window."""
    from datetime import timedelta

    c = conn or get_conn()
    now_dt = now or utcnow()
    now_s = iso(now_dt)
    cutoff = iso(now_dt - timedelta(minutes=60))
    return c.execute(
        """
        SELECT * FROM provider_results
        WHERE indicator_id=? AND provider=?
          AND queried_at > ?
          AND (expires_at IS NULL OR expires_at > ?)
          AND status IN ('ok','not_found')
        ORDER BY queried_at DESC LIMIT 1
        """,
        (indicator_id, provider, cutoff, now_s),
    ).fetchone()


def row_to_result(row: sqlite3.Row, provider_name: str) -> ProviderResult:
    facts = [Fact(**x) for x in json.loads(row["facts_json"] or "[]")]
    related_raw = json.loads(row["related_json"] or "[]")
    related = [
        Related(type=IndicatorType(r["type"]), value=r["value"], relation=r["relation"])
        for r in related_raw
    ]
    status = ResultStatus(row["status"])
    verdict = Verdict(row["verdict"]) if row["verdict"] else None
    raw_blob = row["raw"] if "raw" in row.keys() else None
    return ProviderResult(
        provider=row["provider"],
        provider_name=provider_name,
        status=status,
        skip_reason=row["skip_reason"],
        verdict=verdict,
        summary=row["summary"] or "",
        facts=facts,
        tags=json.loads(row["tags_json"] or "[]"),
        related=related,
        open_source_url=row["open_source_url"],
        queried_at=_parse_iso(row["queried_at"]),
        expires_at=_parse_iso(row["expires_at"]),
        cached=True,
        result_id=row["id"],
        quota=json.loads(row["quota_json"]) if row["quota_json"] else None,
        raw=raw_blob,
    )


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    from datetime import timezone

    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def search_history(q: str, limit: int = 50) -> list[sqlite3.Row]:
    c = get_conn()
    if not q.strip():
        return c.execute(
            "SELECT * FROM indicators ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    # FTS then fallback LIKE
    try:
        rows = c.execute(
            """
            SELECT DISTINCT i.*
            FROM fts_history f
            JOIN indicators i ON i.id = f.indicator_id
            WHERE f MATCH ?
            ORDER BY i.last_seen DESC
            LIMIT ?
            """,
            (q, limit),
        ).fetchall()
        if rows:
            return rows
    except sqlite3.OperationalError:
        pass
    like = f"%{q}%"
    return c.execute(
        "SELECT * FROM indicators WHERE value LIKE ? OR original LIKE ? ORDER BY last_seen DESC LIMIT ?",
        (like, like, limit),
    ).fetchall()


def forget_indicator(indicator_id: int) -> None:
    c = get_conn()
    lookup_ids = [
        r["id"]
        for r in c.execute("SELECT id FROM lookups WHERE indicator_id=?", (indicator_id,)).fetchall()
    ]
    result_ids = [
        r["id"]
        for r in c.execute(
            "SELECT id FROM provider_results WHERE indicator_id=?", (indicator_id,)
        ).fetchall()
    ]
    for lid in lookup_ids:
        c.execute("DELETE FROM lookup_results WHERE lookup_id=?", (lid,))
    if result_ids:
        c.executemany("DELETE FROM lookup_results WHERE result_id=?", [(x,) for x in result_ids])
    c.execute("DELETE FROM edges WHERE from_indicator_id=?", (indicator_id,))
    c.execute("DELETE FROM provider_results WHERE indicator_id=?", (indicator_id,))
    c.execute("DELETE FROM lookups WHERE indicator_id=?", (indicator_id,))
    c.execute("DELETE FROM indicators WHERE id=?", (indicator_id,))
    try:
        c.execute("DELETE FROM fts_history WHERE indicator_id=?", (indicator_id,))
    except sqlite3.OperationalError:
        pass
    c.commit()


def graph_around(ind_type: str, value: str, depth: int = 2) -> dict[str, Any]:
    c = get_conn()
    row = c.execute(
        "SELECT * FROM indicators WHERE type=? AND value=?", (ind_type, value)
    ).fetchone()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(t: str, v: str) -> str:
        nid = f"{t}:{v}"
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": t, "value": v}
        return nid

    if row:
        add_node(row["type"], row["value"])
        rows = c.execute(
            "SELECT * FROM edges WHERE from_indicator_id=? ORDER BY created_at DESC LIMIT 200",
            (row["id"],),
        ).fetchall()
        for e in rows:
            src = add_node(row["type"], row["value"])
            dst = add_node(e["to_type"], e["to_value"])
            edges.append(
                {
                    "from": src,
                    "to": dst,
                    "relation": e["relation"],
                    "provider": e["provider"],
                }
            )
        # reverse edges
        rev = c.execute(
            "SELECT e.*, i.type AS from_type, i.value AS from_value FROM edges e "
            "JOIN indicators i ON i.id = e.from_indicator_id "
            "WHERE e.to_type=? AND e.to_value=? LIMIT 200",
            (ind_type, value),
        ).fetchall()
        for e in rev:
            src = add_node(e["from_type"], e["from_value"])
            dst = add_node(ind_type, value)
            edges.append(
                {
                    "from": src,
                    "to": dst,
                    "relation": e["relation"],
                    "provider": e["provider"],
                }
            )
    return {"nodes": list(nodes.values()), "edges": edges}


def lookup_bundle(lookup_id: str) -> dict[str, Any] | None:
    c = get_conn()
    lu = c.execute("SELECT * FROM lookups WHERE id=?", (lookup_id,)).fetchone()
    if not lu:
        return None
    ind = c.execute("SELECT * FROM indicators WHERE id=?", (lu["indicator_id"],)).fetchone()
    results = c.execute(
        """
        SELECT pr.* FROM provider_results pr
        JOIN lookup_results lr ON lr.result_id = pr.id
        WHERE lr.lookup_id=?
        ORDER BY pr.id
        """,
        (lookup_id,),
    ).fetchall()
    children = c.execute(
        "SELECT * FROM lookups WHERE parent_lookup_id=?", (lookup_id,)
    ).fetchall()
    return {"lookup": lu, "indicator": ind, "results": results, "children": children}


def active_analyst_verdict(indicator_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    c = conn or get_conn()
    row = c.execute(
        "SELECT * FROM analyst_verdicts WHERE indicator_id=? ORDER BY created_at DESC LIMIT 1",
        (indicator_id,),
    ).fetchone()
    return dict(row) if row else None


def analyst_history(indicator_id: int, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    c = conn or get_conn()
    rows = c.execute(
        "SELECT * FROM analyst_verdicts WHERE indicator_id=? ORDER BY created_at DESC LIMIT 50",
        (indicator_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_analyst_verdict(indicator_id: int, verdict: str, note: str = "") -> dict[str, Any]:
    c = get_conn()
    now = iso(utcnow())
    cur = c.execute(
        "INSERT INTO analyst_verdicts(indicator_id, verdict, note, created_at) VALUES (?,?,?,?)",
        (indicator_id, verdict, note, now),
    )
    c.execute("UPDATE indicators SET note=? WHERE id=?", (note or None, indicator_id))
    c.commit()
    return {
        "id": int(cur.lastrowid),
        "indicator_id": indicator_id,
        "verdict": verdict,
        "note": note,
        "created_at": now,
    }


def verdicts_for_values(pairs: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    """Map 'type:value' → active analyst verdict for pivot tagging."""
    if not pairs:
        return {}
    c = get_conn()
    out: dict[str, dict[str, Any]] = {}
    for t, v in pairs:
        row = c.execute(
            """
            SELECT av.verdict, av.note, av.created_at, i.id
            FROM indicators i
            JOIN analyst_verdicts av ON av.indicator_id = i.id
            WHERE i.type=? AND i.value=?
            ORDER BY av.created_at DESC LIMIT 1
            """,
            (t, v),
        ).fetchone()
        if row:
            out[f"{t}:{v}"] = dict(row)
    return out


def rebuild_fts(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    c = conn or get_conn()
    c.execute("DROP TABLE IF EXISTS fts_history")
    created = False
    try:
        c.execute(
            "CREATE VIRTUAL TABLE fts_history USING fts5("
            "value, tags, facts, summary, raw, indicator_id UNINDEXED, type UNINDEXED, tokenize='trigram')"
        )
        created = True
    except sqlite3.OperationalError:
        c.execute(
            "CREATE VIRTUAL TABLE fts_history USING fts5("
            "value, tags, facts, summary, raw, indicator_id UNINDEXED, type UNINDEXED)"
        )
    n = 0
    for ind in c.execute("SELECT * FROM indicators").fetchall():
        c.execute(
            "INSERT INTO fts_history(value, tags, facts, summary, raw, indicator_id, type) VALUES (?,?,?,?,?,?,?)",
            (ind["value"], "", "", "", "", ind["id"], ind["type"]),
        )
        n += 1
    for row in c.execute("SELECT * FROM provider_results").fetchall():
        tags = " ".join(json.loads(row["tags_json"] or "[]"))
        facts = " ".join(
            f"{x.get('label','')} {x.get('value','')}" for x in json.loads(row["facts_json"] or "[]")
        )
        raw_txt = (decompress_raw(row["raw"]) or "")[:8000]
        c.execute(
            "INSERT INTO fts_history(value, tags, facts, summary, raw, indicator_id, type) VALUES (?,?,?,?,?,?,?)",
            ("", tags, facts, row["summary"] or "", raw_txt, row["indicator_id"], ""),
        )
        n += 1
    c.commit()
    return {"ok": True, "rows": n, "trigram": created}


def integrity_check() -> dict[str, Any]:
    c = get_conn()
    row = c.execute("PRAGMA integrity_check").fetchone()
    msg = row[0] if row else "unknown"
    counts = {
        "indicators": c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
        "lookups": c.execute("SELECT COUNT(*) FROM lookups").fetchone()[0],
        "results": c.execute("SELECT COUNT(*) FROM provider_results").fetchone()[0],
        "edges": c.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
        "verdicts": c.execute("SELECT COUNT(*) FROM analyst_verdicts").fetchone()[0],
    }
    return {"ok": msg == "ok", "integrity": msg, "counts": counts}


def snapshot_db(reason: str = "manual") -> dict[str, Any]:
    import shutil

    ensure_data_dir()
    src = Path(str(get_conn().execute("PRAGMA database_list").fetchone()["file"]) or DB_PATH)
    if not src.exists():
        src = DB_PATH
    snap_dir = DATA_DIR / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    name = f"osint-{iso(utcnow()) or 'snap'}.sqlite3".replace(":", "")
    dest = snap_dir / name
    get_conn().execute("PRAGMA wal_checkpoint(PASSIVE)")
    shutil.copy2(src, dest)
    return {"ok": True, "path": str(dest), "reason": reason}


def prune(
    *,
    older_than_days: int = 30,
    strip_raw: bool = False,
    delete_lookups: bool = False,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Keep the newest lookup per indicator+provider. Dry-run first."""
    from datetime import timedelta

    c = get_conn()
    cutoff = iso(utcnow() - timedelta(days=older_than_days))
    old = c.execute(
        "SELECT id, indicator_id, provider, queried_at, LENGTH(raw) AS raw_len FROM provider_results WHERE queried_at < ?",
        (cutoff,),
    ).fetchall()
    keep = set()
    for row in c.execute(
        "SELECT indicator_id, provider, MAX(id) AS mid FROM provider_results GROUP BY indicator_id, provider"
    ).fetchall():
        keep.add(int(row["mid"]))
    candidates = [dict(r) for r in old if int(r["id"]) not in keep]
    raw_bytes = sum(int(r.get("raw_len") or 0) for r in candidates)
    planned = {
        "dry_run": dry_run,
        "cutoff": cutoff,
        "candidates": len(candidates),
        "raw_bytes": raw_bytes,
        "strip_raw": strip_raw,
        "delete_lookups": delete_lookups,
    }
    if dry_run:
        return planned
    snapshot_db("pre-prune")
    ids = [int(r["id"]) for r in candidates]
    if strip_raw and ids:
        c.executemany("UPDATE provider_results SET raw=NULL WHERE id=?", [(i,) for i in ids])
    if delete_lookups and ids:
        c.executemany("DELETE FROM lookup_results WHERE result_id=?", [(i,) for i in ids])
        c.executemany("DELETE FROM provider_results WHERE id=?", [(i,) for i in ids])
        # lookups with no remaining results
        c.execute(
            "DELETE FROM lookups WHERE finished_at < ? AND id NOT IN (SELECT lookup_id FROM lookup_results)",
            (cutoff,),
        )
    c.commit()
    planned["applied"] = True
    return planned


def export_history(fmt: str = "json", limit: int = 5000) -> str:
    c = get_conn()
    rows = c.execute(
        """
        SELECT i.id, i.type, i.value, i.original, i.first_seen, i.last_seen, i.lookup_count,
               (SELECT av.verdict FROM analyst_verdicts av WHERE av.indicator_id=i.id ORDER BY av.created_at DESC LIMIT 1) AS analyst_verdict
        FROM indicators i
        ORDER BY i.last_seen DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    items = [dict(r) for r in rows]
    if fmt == "csv":
        import csv
        import io

        buf = io.StringIO()
        w = csv.DictWriter(
            buf,
            fieldnames=[
                "type",
                "value",
                "original",
                "first_seen",
                "last_seen",
                "lookup_count",
                "analyst_verdict",
            ],
        )
        w.writeheader()
        for it in items:
            w.writerow({k: it.get(k) for k in w.fieldnames})
        return buf.getvalue()
    results = c.execute(
        """
        SELECT i.type, i.value, pr.provider, pr.status, pr.verdict, pr.summary,
               pr.queried_at, pr.tags_json
        FROM provider_results pr
        JOIN indicators i ON i.id = pr.indicator_id
        ORDER BY pr.queried_at DESC
        LIMIT ?
        """,
        (limit * 8,),
    ).fetchall()
    result_items = []
    for r in results:
        d = dict(r)
        try:
            d["tags"] = json.loads(d.pop("tags_json") or "[]")
        except json.JSONDecodeError:
            d["tags"] = []
            d.pop("tags_json", None)
        result_items.append(d)
    return json.dumps({"indicators": items, "results": result_items}, indent=2)

def result_raw(result_id: int) -> str | None:
    c = get_conn()
    row = c.execute("SELECT raw FROM provider_results WHERE id=?", (result_id,)).fetchone()
    if not row:
        return None
    return decompress_raw(row["raw"])

