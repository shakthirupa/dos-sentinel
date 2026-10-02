"""
DoS Sentinel v4.0 — Persistence Layer
======================================
Handles all SQLite read/write operations.

Responsibilities:
  - Schema creation and migration
  - Event persistence and retrieval
  - Blocked-IP management
  - Aggregate query helpers

NOT responsible for:
  - Detection logic
  - Network collection
  - ML inference
"""

import logging
import sqlite3
import threading
from datetime import datetime
from typing import Optional

from config import (
    ATTACK_LOG_API_MAX,
    ATTACK_LOG_DISPLAY_LIMIT,
    DB_FILE,
    EVENTS_DISPLAY_LIMIT,
    TOP_SOURCES_LIMIT,
)

log = logging.getLogger(__name__)

_local = threading.local()

# ── All columns that must exist in the events table ───────────────────────────
# Tuples of (column_name, column_definition).
# Columns present in the original v3 schema are listed first so migration
# only adds what is genuinely missing.
_EVENTS_COLUMNS: list[tuple[str, str]] = [
    # v3 original
    ("id",                "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("ts",                "TEXT"),
    ("status",            "TEXT"),          # kept for app.py compat (= detection)
    ("risk",              "TEXT"),
    ("syn_recv",          "INTEGER"),
    ("conns",             "INTEGER"),       # kept for app.py compat (= total_connections)
    ("velocity",          "REAL"),
    ("score",             "REAL"),
    ("message",           "TEXT"),
    # v3.1 addition (may already exist on some installs)
    ("attack_type",       "TEXT DEFAULT '-'"),
    # v4 additions
    ("detection",         "TEXT"),          # NORMAL / ANOMALY / COOLDOWN
    ("confidence",        "TEXT"),          # LOW / MEDIUM / HIGH
    ("attack_type_source","TEXT"),          # rule_based / none
    ("established",       "INTEGER"),
    ("bytes_sent_per_sec","REAL"),
    ("bytes_recv_per_sec","REAL"),
    ("source_ip",         "TEXT"),          # NULL when not applicable
]

_EVENTS_COLUMN_NAMES = {col for col, _ in _EVENTS_COLUMNS}


# ── Connection management ──────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection, creating it if needed."""
    if not getattr(_local, "conn", None):
        _local.conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


# ── Schema helpers ─────────────────────────────────────────────────────────────

def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _migrate_events(conn: sqlite3.Connection):
    """Add any missing v4 columns to an existing events table."""
    existing = _existing_columns(conn, "events")
    added = []
    for col, defn in _EVENTS_COLUMNS:
        if col in ("id",):          # PRIMARY KEY cannot be added via ALTER
            continue
        if col not in existing:
            # SQLite ALTER TABLE ADD COLUMN does not support all constraints;
            # strip PRIMARY KEY / AUTOINCREMENT if somehow present.
            safe_defn = defn.replace("PRIMARY KEY AUTOINCREMENT", "").strip()
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {safe_defn}")
            added.append(col)
    if added:
        log.info("Migrated events table — added columns: %s", added)


def _ensure_indexes(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_events_ts
            ON events (ts);
        CREATE INDEX IF NOT EXISTS idx_events_detection
            ON events (detection);
        CREATE INDEX IF NOT EXISTS idx_events_status
            ON events (status);
        CREATE INDEX IF NOT EXISTS idx_events_attack_type
            ON events (attack_type);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events (source_ip);
    """)


# ── Public: initialisation ─────────────────────────────────────────────────────

def init_db():
    """Create tables (if absent) and apply any pending schema migrations."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            ts                 TEXT,
            status             TEXT,
            risk               TEXT,
            syn_recv           INTEGER,
            conns              INTEGER,
            velocity           REAL,
            score              REAL,
            message            TEXT,
            attack_type        TEXT    DEFAULT '-',
            detection          TEXT,
            confidence         TEXT,
            attack_type_source TEXT,
            established        INTEGER,
            bytes_sent_per_sec REAL,
            bytes_recv_per_sec REAL,
            source_ip          TEXT
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip         TEXT PRIMARY KEY,
            blocked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS stats (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    _migrate_events(conn)
    _ensure_indexes(conn)
    conn.commit()
    log.info("Database ready — %s", DB_FILE)


# ── Public: event persistence ──────────────────────────────────────────────────

def insert_event(
    result: dict,
    traffic: dict,
    source_ip: Optional[str] = None,
    conn_velocity: float = 0.0,
    message: str = "",
) -> None:
    """
    Persist a detection result produced by DetectionEngine.predict().

    Parameters
    ----------
    result      : dict returned by DetectionEngine.predict()
    traffic     : raw traffic dict (must contain the 5 v4 feature keys)
    source_ip   : dominant source IP for this tick, or None
    conn_velocity: connection velocity (conns/sec) from the collector
    message     : human-readable summary line for the dashboard feed
    """
    detection = result.get("detection", "NORMAL")
    feats     = result.get("features", traffic)

    _get_conn().execute("""
        INSERT INTO events (
            ts, status, risk, syn_recv, conns, velocity, score, message, attack_type,
            detection, confidence, attack_type_source,
            established, bytes_sent_per_sec, bytes_recv_per_sec, source_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%H:%M:%S"),
        detection,                              # status mirrors detection
        result.get("risk"),
        feats.get("syn_recv"),
        feats.get("total_connections"),
        conn_velocity,
        result.get("score"),
        message,
        result.get("attack_type", "-"),
        detection,
        result.get("confidence"),
        result.get("attack_type_source"),
        feats.get("established"),
        feats.get("bytes_sent_per_sec"),
        feats.get("bytes_recv_per_sec"),
        source_ip,
    ))
    _get_conn().commit()


def save_event(ev: dict) -> None:
    """
    Backward-compatible shim for app.py (v3 call signature).

    Accepts the event dict built by app.py's collect_snapshot():
        time, status, risk, syn_recv, connections, velocity,
        score, message, attack_type
    """
    _get_conn().execute("""
        INSERT INTO events (ts, status, risk, syn_recv, conns, velocity, score, message, attack_type,
                            detection)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ev.get("time"),
        ev.get("status"),
        ev.get("risk"),
        ev.get("syn_recv"),
        ev.get("connections"),
        ev.get("velocity", 0),
        ev.get("score"),
        ev.get("message"),
        ev.get("attack_type", "-"),
        ev.get("status"),       # detection mirrors status in v3 events
    ))
    _get_conn().commit()


# ── Public: event retrieval ────────────────────────────────────────────────────

def get_recent_events(limit: int = EVENTS_DISPLAY_LIMIT) -> list[dict]:
    """Return the most recent `limit` events, newest first."""
    rows = _get_conn().execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_attack_log(limit: int = ATTACK_LOG_DISPLAY_LIMIT) -> list[dict]:
    """Return the most recent `limit` ANOMALY events, newest first."""
    rows = _get_conn().execute(
        "SELECT * FROM events WHERE status='ANOMALY' ORDER BY id DESC LIMIT ?",
        (min(limit, ATTACK_LOG_API_MAX),)
    ).fetchall()
    return [dict(r) for r in rows]


def get_event_counts() -> dict:
    """Return total event count and per-detection breakdown in one query."""
    row = _get_conn().execute("""
        SELECT
            COUNT(*)                                    AS total,
            SUM(CASE WHEN status='ANOMALY'  THEN 1 ELSE 0 END) AS anomalies,
            SUM(CASE WHEN status='COOLDOWN' THEN 1 ELSE 0 END) AS cooldowns,
            SUM(CASE WHEN status='NORMAL'   THEN 1 ELSE 0 END) AS normals
        FROM events
    """).fetchone()
    return {
        "total":     row["total"]     or 0,
        "anomalies": row["anomalies"] or 0,
        "cooldowns": row["cooldowns"] or 0,
        "normals":   row["normals"]   or 0,
    }


def get_top_source_ips(limit: int = TOP_SOURCES_LIMIT) -> list[dict]:
    """Return the top `limit` source IPs by anomaly event count."""
    rows = _get_conn().execute("""
        SELECT source_ip, COUNT(*) AS hit_count
        FROM events
        WHERE status='ANOMALY' AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY hit_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── Kept for app.py compat ─────────────────────────────────────────────────────

def get_total_events() -> int:
    row = _get_conn().execute("SELECT COUNT(*) AS c FROM events").fetchone()
    return row["c"] if row else 0


def get_total_anomalies() -> int:
    row = _get_conn().execute(
        "SELECT COUNT(*) AS c FROM events WHERE status='ANOMALY'"
    ).fetchone()
    return row["c"] if row else 0


# ── Public: blocked IPs ────────────────────────────────────────────────────────

def add_blocked_ip(ip: str) -> None:
    """Add or refresh a blocked IP entry."""
    _get_conn().execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at) VALUES (?, ?)",
        (ip, datetime.now().isoformat())
    )
    _get_conn().commit()


def remove_blocked_ip(ip: str) -> None:
    _get_conn().execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    _get_conn().commit()


def get_blocked_ips() -> set:
    rows = _get_conn().execute("SELECT ip FROM blocked_ips").fetchall()
    return {r["ip"] for r in rows}


# ── Optional maintenance ───────────────────────────────────────────────────────

def clear_old_events(keep_last: int = 10_000) -> int:
    """
    Delete events older than the most recent `keep_last` rows.
    Returns the number of rows deleted.
    """
    conn = _get_conn()
    result = conn.execute("""
        DELETE FROM events WHERE id NOT IN (
            SELECT id FROM events ORDER BY id DESC LIMIT ?
        )
    """, (keep_last,))
    conn.commit()
    deleted = result.rowcount
    if deleted:
        log.info("Pruned %d old events (kept last %d)", deleted, keep_last)
    return deleted
