"""
DoS Sentinel v4.0 — Protected Target Server (port 8000)
=========================================================
A lightweight Flask server that acts as the attack target for the
DoS Sentinel demo.  It collects HTTP-layer telemetry so the dashboard
can correlate TCP-level anomalies with actual request patterns.

Telemetry is collected via Flask request hooks — no psutil, no ML model.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from flask import Flask, g, jsonify, request

# ── Telemetry state ────────────────────────────────────────────────────────────

# Sliding window: store the epoch timestamp of each recent request.
# maxlen=600 caps memory at ~600 floats (~5 KB) even under heavy load.
_WINDOW_MAXLEN   = 600
# How many seconds back to count for requests_per_sec.
_RPS_WINDOW_SECS = 1.0
# How many recent response-time samples to average.
_RT_WINDOW_MAXLEN = 200


@dataclass
class _Telemetry:
    total_requests:  int = 0
    status_2xx:      int = 0
    status_3xx:      int = 0
    status_4xx:      int = 0
    status_5xx:      int = 0
    # Bounded sliding windows — never grow beyond their maxlen
    request_times:   deque = field(default_factory=lambda: deque(maxlen=_WINDOW_MAXLEN))
    response_times_ms: deque = field(default_factory=lambda: deque(maxlen=_RT_WINDOW_MAXLEN))


_stats = _Telemetry()
_lock  = threading.Lock()


def _record_request(status_code: int, elapsed_ms: float) -> None:
    """Update all telemetry counters. Called from after_request hook."""
    now = time.monotonic()
    with _lock:
        _stats.total_requests += 1
        _stats.request_times.append(now)
        _stats.response_times_ms.append(elapsed_ms)
        if   200 <= status_code < 300: _stats.status_2xx += 1
        elif 300 <= status_code < 400: _stats.status_3xx += 1
        elif 400 <= status_code < 500: _stats.status_4xx += 1
        elif 500 <= status_code < 600: _stats.status_5xx += 1


def _snapshot() -> dict:
    """Return a consistent telemetry snapshot under the lock."""
    now = time.monotonic()
    with _lock:
        cutoff = now - _RPS_WINDOW_SECS
        rps    = sum(1 for t in _stats.request_times if t >= cutoff)
        avg_rt = (
            round(sum(_stats.response_times_ms) / len(_stats.response_times_ms), 2)
            if _stats.response_times_ms else 0.0
        )
        return {
            "total_requests":      _stats.total_requests,
            "requests_per_sec":    rps,
            "successful_responses": _stats.status_2xx,
            "error_responses":     _stats.status_4xx + _stats.status_5xx,
            "avg_response_time_ms": avg_rt,
            "status_codes": {
                "2xx": _stats.status_2xx,
                "3xx": _stats.status_3xx,
                "4xx": _stats.status_4xx,
                "5xx": _stats.status_5xx,
            },
        }


# ── Flask app ──────────────────────────────────────────────────────────────────

server = Flask(__name__)

# Paths excluded from telemetry to avoid self-referential noise.
_TELEMETRY_PATHS = {"/api/telemetry"}


@server.before_request
def _before() -> None:
    """Record request start time unless this is a telemetry poll."""
    if request.path not in _TELEMETRY_PATHS:
        g._start_time = time.monotonic()


@server.after_request
def _after(response):
    """Record elapsed time and status code for non-telemetry requests."""
    start = getattr(g, "_start_time", None)
    if start is not None:
        elapsed_ms = (time.monotonic() - start) * 1000
        _record_request(response.status_code, elapsed_ms)
    return response


# ── Existing routes (unchanged) ────────────────────────────────────────────────

@server.route("/")
def home() -> str:
    return f"""
    <html>
        <head><title>Protected Server</title></head>
        <body>
            <h1>Protected Server is Running</h1>
            <p>Server Time: {datetime.now()}</p>
        </body>
    </html>
    """


@server.route("/api/test")
def test() -> dict:
    return {
        "status":  "online",
        "message": "Protected server is working",
    }


# ── Telemetry endpoint ─────────────────────────────────────────────────────────

@server.route("/api/telemetry")
def telemetry():
    """
    Return HTTP-layer telemetry for the current server process.

    Requests to this endpoint are excluded from the counters so that
    dashboard polling does not inflate the request rate.
    """
    return jsonify(_snapshot())


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Protected server  →  http://127.0.0.1:8000")
    server.run(host="127.0.0.1", port=8000, debug=False)
