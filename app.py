import eventlet
eventlet.monkey_patch()

import logging
import os
import re
import subprocess
import sys
import threading
import time
import ipaddress
import urllib.request
import json
from collections import defaultdict, deque
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

import database as db
from engine import DetectionEngine
from config import (
    AUTO_BLOCK_THRESHOLD,
    ATTACK_LOG_API_MAX,
    EVENTS_DEQUE_SIZE,
    EVENTS_DISPLAY_LIMIT,
    ATTACK_LOG_DISPLAY_LIMIT,
    IP_ANOMALY_MAX_KEYS,
    IP_HISTORY_TICKS,
    NETWORK_GAUGE_DIVISOR,
    PUSH_INTERVAL,
    TOP_SOURCES_LIMIT,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ── DB + Engine init ───────────────────────────────────────────────────────────
db.init_db()

try:
    engine = DetectionEngine()
    _engine_ok = True
    log.info("DetectionEngine ready — model %s", engine._meta.get("model_version"))
except Exception as e:
    log.error("DetectionEngine failed to load: %s", e)
    engine     = None
    _engine_ok = False

# ── Runtime state ──────────────────────────────────────────────────────────────
_prev_net        = psutil.net_io_counters()
_prev_time       = datetime.now()
_prev_conn_count = 0

events     = deque(maxlen=EVENTS_DEQUE_SIZE)
ip_history = defaultdict(lambda: deque(maxlen=IP_HISTORY_TICKS))
blocked_ips = db.get_blocked_ips()

auto_block_enabled   = True
auto_block_threshold = AUTO_BLOCK_THRESHOLD
ip_anomaly_counts    = defaultdict(int)

uptime_start = datetime.now()

VALID_ATTACKS     = {"syn", "http", "slowloris", "exhaust"}
VALID_INTENSITIES = {"low", "medium", "high"}
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# ── HTTP telemetry cache ───────────────────────────────────────────────────────
_http_telemetry_cache: dict = {}
_http_telemetry_ts: float   = 0.0
_HTTP_TELEMETRY_URL          = "http://127.0.0.1:8000/api/telemetry"
_HTTP_CACHE_TTL              = 2.0   # seconds — avoid fetching on every 1s tick

_NULL_HTTP_TELEMETRY = {
    "total_requests":       0,
    "requests_per_sec":     0,
    "successful_responses": 0,
    "error_responses":      0,
    "avg_response_time_ms": 0.0,
    "status_codes":         {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
    "available":            False,
}


def is_valid_ip(ip: str) -> bool:
    if not IP_REGEX.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


# ── HTTP telemetry ─────────────────────────────────────────────────────────────

def get_http_telemetry() -> dict:
    """
    Fetch telemetry from the local protected server (127.0.0.1:8000).
    Results are cached for _HTTP_CACHE_TTL seconds to avoid per-tick overhead.
    Returns _NULL_HTTP_TELEMETRY if the server is unreachable.
    """
    global _http_telemetry_cache, _http_telemetry_ts
    now = time.monotonic()
    if now - _http_telemetry_ts < _HTTP_CACHE_TTL and _http_telemetry_cache:
        return _http_telemetry_cache
    try:
        with urllib.request.urlopen(_HTTP_TELEMETRY_URL, timeout=0.5) as r:
            data = json.loads(r.read())
            data["available"] = True
            _http_telemetry_cache = data
            _http_telemetry_ts    = now
            return data
    except Exception:
        _http_telemetry_cache = _NULL_HTTP_TELEMETRY.copy()
        _http_telemetry_ts    = now
        return _http_telemetry_cache


# ── Network collection ─────────────────────────────────────────────────────────

def get_network_data() -> dict:
    """Collect one TCP/network snapshot. Returns the 5 v4 features + extras."""
    global _prev_net, _prev_time, _prev_conn_count

    try:
        connections = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        log.warning("psutil.net_connections requires Administrator on Windows.")
        connections = []

    syn_recv = established = 0
    source_ips: dict[str, int] = {}

    for c in connections:
        if c.status == psutil.CONN_SYN_RECV:
            syn_recv += 1
        elif c.status == psutil.CONN_ESTABLISHED:
            established += 1
        if c.raddr:
            try:
                ip = c.raddr.ip
                source_ips[ip] = source_ips.get(ip, 0) + 1
            except Exception:
                pass

    total   = len(connections)
    now     = datetime.now()
    elapsed = max((now - _prev_time).total_seconds(), 1)

    cur     = psutil.net_io_counters()
    sent_ps = max((cur.bytes_sent - _prev_net.bytes_sent) / elapsed, 0)
    recv_ps = max((cur.bytes_recv - _prev_net.bytes_recv) / elapsed, 0)
    vel     = max((total - _prev_conn_count) / elapsed, 0)

    _prev_net        = cur
    _prev_time       = now
    _prev_conn_count = total

    return {
        # v4 ML features
        "syn_recv":           syn_recv,
        "established":        established,
        "total_connections":  total,
        "bytes_sent_per_sec": round(sent_ps, 2),
        "bytes_recv_per_sec": round(recv_ps, 2),
        # rule-based classifier extra (optional in engine)
        "conn_velocity":      round(vel, 2),
        # dashboard extras
        "source_ips":         source_ips,
    }


# ── Auto-block ─────────────────────────────────────────────────────────────────

# Private/loopback/link-local networks that must never be auto-blocked.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    """Return True if ip is loopback, private, or link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True   # unparseable — treat as private to be safe


def maybe_auto_block(source_ip: str | None, detection: str) -> None:
    """Increment anomaly counter for the single dominant source IP.

    Only acts when detection == ANOMALY and source_ip is a routable
    public address.  Private, loopback, and link-local addresses are
    never auto-blocked.
    """
    if not auto_block_enabled or detection != "ANOMALY":
        return
    if not source_ip:
        return
    if _is_private(source_ip):
        return
    if source_ip in blocked_ips:
        return
    if len(ip_anomaly_counts) > IP_ANOMALY_MAX_KEYS:
        oldest = sorted(ip_anomaly_counts, key=lambda k: ip_anomaly_counts[k])[:100]
        for k in oldest:
            del ip_anomaly_counts[k]
    ip_anomaly_counts[source_ip] += 1
    if ip_anomaly_counts[source_ip] >= auto_block_threshold:
        blocked_ips.add(source_ip)
        db.add_blocked_ip(source_ip)
        ip_anomaly_counts[source_ip] = 0
        socketio.emit("ip_auto_blocked", {"ip": source_ip})
        log.info("Auto-blocked %s", source_ip)


# ── Snapshot ───────────────────────────────────────────────────────────────────

def collect_snapshot() -> tuple:
    """
    Collect traffic, run detection, persist event.
    Returns (traffic, result, ts, event_dict).
    result is the DetectionEngine output dict, or a safe fallback if engine failed.
    """
    traffic = get_network_data()

    if _engine_ok and engine is not None:
        try:
            result = engine.predict(traffic)
        except Exception as e:
            log.error("engine.predict() failed: %s", e)
            result = _fallback_result()
    else:
        result = _fallback_result()

    detection   = result["detection"]
    score       = result["score"]
    risk        = result["risk"]
    attack_type = result["attack_type"]
    ts          = datetime.now().strftime("%H:%M:%S")

    for ip, cnt in traffic["source_ips"].items():
        ip_history[ip].append(cnt)

    # Build the dominant source IP for this tick
    source_ip = (
        max(traffic["source_ips"], key=traffic["source_ips"].get)
        if traffic["source_ips"] else None
    )

    message = (
        f"[{attack_type}] Possible DoS anomaly" if detection == "ANOMALY"
        else ("Cooling down..." if detection == "COOLDOWN"
        else ("Suspicious pattern" if score < 0 else "Normal traffic"))
    )

    # Persist via v4 insert_event
    try:
        db.insert_event(
            result=result,
            traffic=traffic,
            source_ip=source_ip,
            conn_velocity=traffic["conn_velocity"],
            message=message,
        )
    except Exception as e:
        log.error("db.insert_event() failed: %s", e)

    # In-memory event for dashboard feed (preserves existing frontend keys)
    event = {
        "time":               ts,
        "status":             detection,
        "risk":               risk,
        "attack_type":        attack_type,
        "attack_type_source": result["attack_type_source"],
        "confidence":         result["confidence"],
        "syn_recv":           traffic["syn_recv"],
        "connections":        traffic["total_connections"],
        "velocity":           traffic["conn_velocity"],
        "score":              round(score, 4),
        "message":            message,
        "model_version":      result["model_version"],
    }
    events.append(event)

    maybe_auto_block(source_ip, detection)
    return traffic, result, ts, event


def _fallback_result() -> dict:
    """Safe result dict when the engine is unavailable."""
    return {
        "detection":          "NORMAL",
        "score":              0.0,
        "confidence":         "LOW",
        "risk":               "LOW",
        "attack_type":        "-",
        "attack_type_source": "none",
        "features":           {},
        "model_version":      "unavailable",
    }


# ── Payload ────────────────────────────────────────────────────────────────────

def build_payload() -> dict:
    traffic, result, ts, _ = collect_snapshot()
    http_tel = get_http_telemetry()

    detection   = result["detection"]
    score       = result["score"]
    risk        = result["risk"]
    attack_type = result["attack_type"]

    sorted_ips  = sorted(traffic["source_ips"].items(), key=lambda x: x[1], reverse=True)
    top_sources = [
        {
            "ip":          ip,
            "connections": cnt,
            "blocked":     ip in blocked_ips,
            "trend":       list(ip_history[ip])[-5:],
        }
        for ip, cnt in sorted_ips[:TOP_SOURCES_LIMIT]
    ]

    cpu     = psutil.cpu_percent(interval=None)
    mem     = psutil.virtual_memory().percent
    net_pct = min(
        int((traffic["bytes_recv_per_sec"] + traffic["bytes_sent_per_sec"]) / NETWORK_GAUGE_DIVISOR),
        100,
    )

    uptime_secs = int((datetime.now() - uptime_start).total_seconds())
    h, rem = divmod(uptime_secs, 3600)
    m, s   = divmod(rem, 60)

    # Single DB round-trip for counts
    try:
        counts = db.get_event_counts()
    except Exception:
        counts = {"total": 0, "anomalies": 0, "cooldowns": 0, "normals": 0}

    model_status = "ACTIVE" if _engine_ok else "ERROR"

    return {
        # v4 detection fields
        "detection":          detection,
        "risk":               risk,
        "attack_type":        attack_type,
        "attack_type_source": result["attack_type_source"],
        "confidence":         result["confidence"],
        "anomaly_score":      round(score, 4),
        "model_version":      result["model_version"],
        # traffic (preserves existing frontend keys)
        "traffic":            traffic,
        # system
        "system": {
            "cpu":     cpu,
            "memory":  mem,
            "network": net_pct,
            "model":   model_status,
        },
        # HTTP telemetry from server.py
        "http_telemetry": http_tel,
        # sources / events
        "sources":    top_sources,
        "events":     list(events)[-EVENTS_DISPLAY_LIMIT:],
        "attack_log": db.get_attack_log(ATTACK_LOG_DISPLAY_LIMIT),
        # stats (one query)
        "stats": {
            "total_events":         counts["total"],
            "total_anomalies":      counts["anomalies"],
            "total_blocked":        len(blocked_ips),
            "blocked_count":        len(blocked_ips),
            "uptime":               f"{h:02d}:{m:02d}:{s:02d}",
            "uptime_start":         uptime_start.isoformat(),
            "auto_block":           auto_block_enabled,
            "auto_block_threshold": auto_block_threshold,
        },
        "blocked_ips": list(blocked_ips),
        "timestamp":   ts,
    }


# ── Background push ────────────────────────────────────────────────────────────

def push_loop() -> None:
    while True:
        try:
            socketio.emit("update", build_payload())
        except Exception as e:
            log.error("WebSocket push error: %s", e)
        time.sleep(PUSH_INTERVAL)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def status():
    # Reuse the latest in-memory snapshot rather than triggering a new collection
    return jsonify(build_payload())


@app.route("/api/block", methods=["POST"])
def block_ip():
    data = request.get_json(silent=True) or {}
    ip   = str(data.get("ip", "")).strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP"}), 400
    blocked_ips.add(ip)
    db.add_blocked_ip(ip)
    socketio.emit("ip_blocked", {"ip": ip})
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json(silent=True) or {}
    ip   = str(data.get("ip", "")).strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP"}), 400
    blocked_ips.discard(ip)
    db.remove_blocked_ip(ip)
    ip_anomaly_counts.pop(ip, None)
    socketio.emit("ip_unblocked", {"ip": ip})
    return jsonify({"ok": True, "ip": ip})


@app.route("/api/attack_log")
def get_attack_log():
    try:
        limit = min(int(request.args.get("limit", 500)), ATTACK_LOG_API_MAX)
    except ValueError:
        limit = 500
    return jsonify(db.get_attack_log(limit))


@app.route("/api/auto_block", methods=["POST"])
def set_auto_block():
    global auto_block_enabled, auto_block_threshold
    data = request.get_json(silent=True) or {}
    if "enabled" in data:
        auto_block_enabled = bool(data["enabled"])
    if "threshold" in data:
        try:
            auto_block_threshold = max(1, min(int(data["threshold"]), 100))
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "Invalid threshold"}), 400
    return jsonify({"ok": True, "enabled": auto_block_enabled, "threshold": auto_block_threshold})


@app.route("/api/simulate", methods=["POST"])
def simulate():
    data      = request.get_json(silent=True) or {}
    attack    = str(data.get("attack", "")).strip()
    intensity = str(data.get("intensity", "medium")).strip()

    if attack not in VALID_ATTACKS:
        return jsonify({"ok": False, "error": f"Invalid attack. Choose from: {VALID_ATTACKS}"}), 400
    if intensity not in VALID_INTENSITIES:
        return jsonify({"ok": False, "error": f"Invalid intensity. Choose from: {VALID_INTENSITIES}"}), 400

    try:
        subprocess.Popen(
            [sys.executable, "simulator.py", "--attack", attack, "--intensity", intensity],
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0,
        )
        return jsonify({"ok": True, "attack": attack, "intensity": intensity})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/stats")
def get_stats():
    counts = db.get_event_counts()
    return jsonify({
        "total_events":    counts["total"],
        "total_anomalies": counts["anomalies"],
        "blocked_count":   len(blocked_ips),
        "auto_block":      auto_block_enabled,
        "threshold":       auto_block_threshold,
    })


# ── SocketIO ───────────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    try:
        socketio.emit("update", build_payload())
    except Exception:
        pass


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    t = threading.Thread(target=push_loop, daemon=True)
    t.start()

    model_ver = engine._meta.get("model_version", "?") if _engine_ok and engine else "ERROR"

    print()
    print("=" * 46)
    print("       DOS SENTINEL  v4.0")
    print("=" * 46)
    print("  Dashboard  ->  http://127.0.0.1:5000")
    print("  Target     ->  http://127.0.0.1:8000")
    print("  DB         ->  sentinel.db")
    print(f"  Model      ->  {model_ver}")
    print("=" * 46)
    print()

    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
