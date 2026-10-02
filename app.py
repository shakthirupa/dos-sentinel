import eventlet
eventlet.monkey_patch()

import os
import re
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO
import psutil
import joblib
import pandas as pd
from datetime import datetime
from collections import deque, defaultdict
import threading
import time
import subprocess
import sys

import database as db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ── Model ──────────────────────────────────────────────────────────────────────
try:
    model = joblib.load("dos_model.pkl")
except FileNotFoundError:
    print("[ERROR] dos_model.pkl not found. Run: python train.py")
    sys.exit(1)

# ── Init DB ────────────────────────────────────────────────────────────────────
db.init_db()

# ── Runtime state ──────────────────────────────────────────────────────────────
previous_network    = psutil.net_io_counters()
previous_time       = datetime.now()
previous_conn_count = 0

events     = deque(maxlen=100)
ip_history = defaultdict(lambda: deque(maxlen=60))

blocked_ips = db.get_blocked_ips()

auto_block_enabled   = True
auto_block_threshold = 3
ip_anomaly_counts    = defaultdict(int)
IP_ANOMALY_MAX_KEYS  = 1000   # prevent unbounded growth

# ── Cooldown state ─────────────────────────────────────────────────────────────
COOLDOWN_TICKS  = 5
cooldown_counter = 0
in_cooldown      = False

uptime_start = datetime.now()

VALID_ATTACKS    = {"syn", "http", "slowloris", "exhaust"}
VALID_INTENSITIES = {"low", "medium", "high"}
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_valid_ip(ip: str) -> bool:
    if not IP_REGEX.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


# ── Attack type classifier ─────────────────────────────────────────────────────

def classify_attack(traffic: dict, score: float) -> str:
    syn   = traffic["syn_recv"]
    est   = traffic["established"]
    total = traffic["total_connections"]
    vel   = traffic["conn_velocity"]
    bps   = traffic["bytes_recv_per_sec"] + traffic["bytes_sent_per_sec"]

    if syn > 20:              return "SYN Flood"
    if bps > 5_000_000:       return "Bandwidth Flood"
    if vel > 15:              return "HTTP Flood"
    if est > 80 and vel < 2:  return "Slowloris"
    if total > 100 and syn < 5: return "Connection Exhaustion"
    return "Unknown DoS"


# ── Network data ───────────────────────────────────────────────────────────────

def get_network_data() -> dict:
    global previous_network, previous_time, previous_conn_count

    try:
        connections = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("[WARN] psutil.net_connections requires admin privileges on Windows.")
        connections = []

    syn_recv = established = 0
    source_ips = {}

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
    elapsed = max((now - previous_time).total_seconds(), 1)

    cur     = psutil.net_io_counters()
    sent_ps = max((cur.bytes_sent - previous_network.bytes_sent) / elapsed, 0)
    recv_ps = max((cur.bytes_recv - previous_network.bytes_recv) / elapsed, 0)
    vel     = max((total - previous_conn_count) / elapsed, 0)

    previous_network    = cur
    previous_time       = now
    previous_conn_count = total

    return {
        "syn_recv":           syn_recv,
        "established":        established,
        "total_connections":  total,
        "bytes_sent_per_sec": round(sent_ps, 2),
        "bytes_recv_per_sec": round(recv_ps, 2),
        "conn_velocity":      round(vel, 2),
        "source_ips":         source_ips,
    }


def detect_anomaly(traffic: dict):
    df = pd.DataFrame([{
        "syn_recv":          traffic["syn_recv"],
        "established":       traffic["established"],
        "total_connections": traffic["total_connections"],
    }])
    pred  = model.predict(df)[0]
    score = float(model.decision_function(df)[0])
    return ("ANOMALY" if pred == -1 else "NORMAL"), score


def risk_level(detection: str, score: float) -> str:
    if detection == "ANOMALY":  return "HIGH"
    if detection == "COOLDOWN": return "LOW"
    if score < 0:               return "MEDIUM"
    return "LOW"


def apply_cooldown(detection: str) -> str:
    global in_cooldown, cooldown_counter
    if detection == "ANOMALY":
        in_cooldown      = True
        cooldown_counter = 0
        return "ANOMALY"
    if in_cooldown:
        cooldown_counter += 1
        if cooldown_counter >= COOLDOWN_TICKS:
            in_cooldown      = False
            cooldown_counter = 0
        else:
            return "COOLDOWN"
    return "NORMAL"


# ── Auto-block ─────────────────────────────────────────────────────────────────

def maybe_auto_block(source_ips: dict, detection: str):
    if not auto_block_enabled or detection != "ANOMALY":
        return
    # Evict oldest entries if dict grows too large
    if len(ip_anomaly_counts) > IP_ANOMALY_MAX_KEYS:
        oldest = sorted(ip_anomaly_counts, key=lambda k: ip_anomaly_counts[k])[:100]
        for k in oldest:
            del ip_anomaly_counts[k]

    for ip, cnt in source_ips.items():
        if ip in blocked_ips:
            continue
        ip_anomaly_counts[ip] += 1
        if ip_anomaly_counts[ip] >= auto_block_threshold:
            blocked_ips.add(ip)
            db.add_blocked_ip(ip)
            ip_anomaly_counts[ip] = 0
            socketio.emit("ip_auto_blocked", {"ip": ip})
            print(f"[AUTO-BLOCK] {ip}")


# ── Collect traffic snapshot ───────────────────────────────────────────────────

def collect_snapshot() -> tuple:
    """Returns (traffic, detection, score, risk, attack_type, ts, event)."""
    traffic          = get_network_data()
    detection, score = detect_anomaly(traffic)
    detection        = apply_cooldown(detection)
    risk             = risk_level(detection, score)
    ts               = datetime.now().strftime("%H:%M:%S")
    attack_type      = classify_attack(traffic, score) if detection == "ANOMALY" else "-"

    for ip, cnt in traffic["source_ips"].items():
        ip_history[ip].append(cnt)

    event = {
        "time":        ts,
        "status":      detection,
        "risk":        risk,
        "attack_type": attack_type,
        "syn_recv":    traffic["syn_recv"],
        "connections": traffic["total_connections"],
        "velocity":    traffic["conn_velocity"],
        "score":       round(score, 4),
        "message": (
            f"[{attack_type}] Possible DoS anomaly" if detection == "ANOMALY"
            else ("Cooling down..." if detection == "COOLDOWN"
            else ("Suspicious pattern" if score < 0 else "Normal traffic"))
        ),
    }
    events.append(event)
    db.save_event(event)
    maybe_auto_block(traffic["source_ips"], detection if detection == "ANOMALY" else "NORMAL")
    return traffic, detection, score, risk, attack_type, ts, event


def build_payload() -> dict:
    traffic, detection, score, risk, attack_type, ts, _ = collect_snapshot()

    sorted_ips  = sorted(traffic["source_ips"].items(), key=lambda x: x[1], reverse=True)
    top_sources = [
        {
            "ip":          ip,
            "connections": cnt,
            "blocked":     ip in blocked_ips,
            "trend":       list(ip_history[ip])[-5:],
        }
        for ip, cnt in sorted_ips[:8]
    ]

    cpu     = psutil.cpu_percent(interval=None)
    mem     = psutil.virtual_memory().percent
    net_pct = min(int((traffic["bytes_recv_per_sec"] + traffic["bytes_sent_per_sec"]) / 100_000), 100)

    uptime_secs = int((datetime.now() - uptime_start).total_seconds())
    h, rem = divmod(uptime_secs, 3600)
    m, s   = divmod(rem, 60)

    return {
        "detection":     detection,
        "risk":          risk,
        "attack_type":   attack_type,
        "anomaly_score": round(score, 4),
        "traffic":       traffic,
        "system":        {"cpu": cpu, "memory": mem, "network": net_pct, "model": "ACTIVE"},
        "sources":       top_sources,
        "events":        list(events)[-15:],
        "attack_log":    db.get_attack_log(20),
        "stats": {
            "total_events":         db.get_total_events(),
            "total_anomalies":      db.get_total_anomalies(),
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

def push_loop():
    while True:
        try:
            socketio.emit("update", build_payload())
        except Exception as e:
            print("Push error:", e)
        time.sleep(1)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def status():
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
        limit = min(int(request.args.get("limit", 500)), 1000)
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
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
        )
        return jsonify({"ok": True, "attack": attack, "intensity": intensity})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/stats")
def get_stats():
    return jsonify({
        "total_events":    db.get_total_events(),
        "total_anomalies": db.get_total_anomalies(),
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

    print()
    print("=" * 46)
    print("       DOS SENTINEL  v3.0")
    print("=" * 46)
    print("  Dashboard  →  http://127.0.0.1:5000")
    print("  Target     →  http://127.0.0.1:8000")
    print("  DB         →  sentinel.db")
    print("=" * 46)
    print()

    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
