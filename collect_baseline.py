"""
Run this for ~2-3 minutes while doing normal activity (browsing, etc.)
It collects real baseline traffic from your machine to retrain the model.
"""
import psutil
import csv
import time
from datetime import datetime

OUTPUT = "real_baseline.csv"
DURATION = 180  # seconds

print(f"Collecting {DURATION}s of baseline traffic → {OUTPUT}")
print("Do NOT run any attacks during this time.\n")

prev_net  = psutil.net_io_counters()
prev_time = time.time()

with open(OUTPUT, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "syn_recv", "established", "total_connections",
                     "bytes_sent", "bytes_received"])

    for i in range(DURATION):
        conns = psutil.net_connections(kind="tcp")
        syn_recv = sum(1 for c in conns if c.status == psutil.CONN_SYN_RECV)
        established = sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
        total = len(conns)

        now     = time.time()
        cur_net = psutil.net_io_counters()
        elapsed = max(now - prev_time, 1)
        sent_ps = int((cur_net.bytes_sent - prev_net.bytes_sent) / elapsed)
        recv_ps = int((cur_net.bytes_recv - prev_net.bytes_recv) / elapsed)

        prev_net  = cur_net
        prev_time = now

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([ts, syn_recv, established, total, sent_ps, recv_ps])

        print(f"[{i+1:3d}/{DURATION}] syn={syn_recv} est={established} total={total}", end="\r")
        time.sleep(1)

print(f"\n\nDone! Saved to {OUTPUT}")
print("Now run: python retrain.py")
