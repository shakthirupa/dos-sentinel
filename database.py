import sqlite3
import threading
from datetime import datetime

DB_FILE  = "sentinel.db"
_local   = threading.local()


def get_conn() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        _local.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT,
            status    TEXT,
            risk      TEXT,
            syn_recv  INTEGER,
            conns     INTEGER,
            velocity  REAL,
            score     REAL,
            message   TEXT,
            attack_type TEXT DEFAULT '-'
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
    conn.commit()


def save_event(ev: dict):
    get_conn().execute("""
        INSERT INTO events (ts, status, risk, syn_recv, conns, velocity, score, message, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ev.get("time"), ev.get("status"), ev.get("risk"),
        ev.get("syn_recv"), ev.get("connections"),
        ev.get("velocity", 0), ev.get("score"),
        ev.get("message"), ev.get("attack_type", "-")
    ))
    get_conn().commit()


def get_attack_log(limit: int = 500) -> list:
    rows = get_conn().execute(
        "SELECT * FROM events WHERE status='ANOMALY' ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_recent_events(limit: int = 100) -> list:
    rows = get_conn().execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def add_blocked_ip(ip: str):
    get_conn().execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at) VALUES (?, ?)",
        (ip, datetime.now().isoformat())
    )
    get_conn().commit()


def remove_blocked_ip(ip: str):
    get_conn().execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    get_conn().commit()


def get_blocked_ips() -> set:
    rows = get_conn().execute("SELECT ip FROM blocked_ips").fetchall()
    return {r["ip"] for r in rows}


def get_total_anomalies() -> int:
    row = get_conn().execute(
        "SELECT COUNT(*) as c FROM events WHERE status='ANOMALY'"
    ).fetchone()
    return row["c"] if row else 0


def get_total_events() -> int:
    row = get_conn().execute("SELECT COUNT(*) as c FROM events").fetchone()
    return row["c"] if row else 0
