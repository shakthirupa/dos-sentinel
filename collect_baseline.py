"""
DoS Sentinel v4.0 — Normal Baseline Collector
===============================================
Collects normal (attack-free) traffic from the local machine and writes
it to a CSV file for use by retrain.py.

Usage:
    python collect_baseline.py                        # 180 s default
    python collect_baseline.py --duration 300
    python collect_baseline.py --duration 60 --output data/my_baseline.csv

Run as Administrator on Windows (required for psutil.net_connections).
Do NOT run any attacks or stress tools during collection.
"""

import argparse
import csv
import math
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

from config import FEATURE_NAMES, PUSH_INTERVAL

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_DURATION = 180          # seconds
DEFAULT_OUTPUT   = Path("data") / "normal_baseline.csv"
MIN_SAMPLES      = 10           # warn if fewer than this are collected


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect normal traffic baseline for DoS Sentinel v4")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                   help=f"Collection duration in seconds (default: {DEFAULT_DURATION})")
    p.add_argument("--output",   type=Path, default=DEFAULT_OUTPUT,
                   help=f"Output CSV path (default: {DEFAULT_OUTPUT})")
    return p.parse_args()


def _get_connections() -> tuple[int, int, int]:
    """Return (syn_recv, established, total) TCP connection counts."""
    try:
        conns = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("\n[ERROR] psutil.net_connections() requires Administrator on Windows.")
        sys.exit(1)
    syn_recv    = sum(1 for c in conns if c.status == psutil.CONN_SYN_RECV)
    established = sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
    return syn_recv, established, len(conns)


def collect(duration: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    total_samples   = 0
    skipped_samples = 0

    print()
    print("=" * 50)
    print("  DoS Sentinel v4 — Baseline Collector")
    print("=" * 50)
    print(f"  Duration : {duration}s")
    print(f"  Output   : {output}")
    print(f"  Interval : {PUSH_INTERVAL}s")
    print()
    print("  Do NOT run any attacks during collection.")
    print("=" * 50)
    print()

    # Prime the network counter — first diff will be against this reading.
    prev_net  = psutil.net_io_counters()
    prev_time = time.monotonic()

    # Sleep one interval so the first real sample has a valid previous counter.
    time.sleep(PUSH_INTERVAL)

    start_wall = time.monotonic()

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "syn_recv", "established", "total_connections",
            "bytes_sent_per_sec", "bytes_recv_per_sec",
        ])

        while (time.monotonic() - start_wall) < duration:
            tick_start = time.monotonic()

            # ── Collect ───────────────────────────────────────────────────────
            syn_recv, established, total = _get_connections()

            cur_net  = psutil.net_io_counters()
            now      = time.monotonic()
            elapsed  = now - prev_time

            # ── Validate elapsed ──────────────────────────────────────────────
            if elapsed <= 0:
                skipped_samples += 1
                prev_net  = cur_net
                prev_time = now
                time.sleep(max(0.0, PUSH_INTERVAL - (time.monotonic() - tick_start)))
                continue

            sent_diff = cur_net.bytes_sent - prev_net.bytes_sent
            recv_diff = cur_net.bytes_recv - prev_net.bytes_recv

            # ── Detect counter reset (OS reboot / interface change) ───────────
            if sent_diff < 0 or recv_diff < 0:
                skipped_samples += 1
                prev_net  = cur_net
                prev_time = now
                print(f"\n  [SKIP] Counter reset detected — skipping sample.")
                time.sleep(max(0.0, PUSH_INTERVAL - (time.monotonic() - tick_start)))
                continue

            bytes_sent_per_sec = round(sent_diff / elapsed, 2)
            bytes_recv_per_sec = round(recv_diff / elapsed, 2)

            # ── Validate feature values ───────────────────────────────────────
            values = [syn_recv, established, total, bytes_sent_per_sec, bytes_recv_per_sec]
            if any(math.isnan(v) or math.isinf(v) or v < 0 for v in values):
                skipped_samples += 1
                prev_net  = cur_net
                prev_time = now
                time.sleep(max(0.0, PUSH_INTERVAL - (time.monotonic() - tick_start)))
                continue

            # ── Write row ─────────────────────────────────────────────────────
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([ts, syn_recv, established, total,
                             bytes_sent_per_sec, bytes_recv_per_sec])
            f.flush()

            total_samples += 1
            prev_net  = cur_net
            prev_time = now

            # ── Progress ──────────────────────────────────────────────────────
            elapsed_wall = int(time.monotonic() - start_wall)
            print(
                f"  [{elapsed_wall:4d}/{duration}s]  "
                f"samples={total_samples}  "
                f"syn={syn_recv}  est={established}  total={total}  "
                f"sent={bytes_sent_per_sec:>10.0f} B/s  "
                f"recv={bytes_recv_per_sec:>10.0f} B/s  "
                f"skipped={skipped_samples}",
                end="\r",
            )

            # ── Sleep remainder of interval ───────────────────────────────────
            time.sleep(max(0.0, PUSH_INTERVAL - (time.monotonic() - tick_start)))

    print()
    print()
    print("=" * 50)
    print(f"  Collection complete.")
    print(f"  Samples collected : {total_samples}")
    print(f"  Samples skipped   : {skipped_samples}")
    print(f"  Output file       : {output}")
    print("=" * 50)

    if total_samples < MIN_SAMPLES:
        print(f"\n  [WARN] Only {total_samples} samples collected.")
        print(f"  Retrain.py requires at least {MIN_SAMPLES}.")
        print(f"  Consider running with a longer --duration.")
    else:
        print(f"\n  Run: python retrain.py --input {output}")
    print()


if __name__ == "__main__":
    args = _parse_args()
    collect(args.duration, args.output)
