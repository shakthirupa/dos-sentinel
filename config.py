"""
DoS Sentinel v4.0 — Central Configuration
==========================================
All hardcoded values from across the project are defined here.
Every other module should import from this file instead of
defining its own constants.
"""

from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
# Root directory of the project (same folder as this file)
BASE_DIR = Path(__file__).parent

# Directory where trained model artifacts are stored.
# Created automatically below if it does not exist.
MODEL_DIR = BASE_DIR / "models"

# Isolation Forest model saved by train.py / retrain.py
MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"

# StandardScaler saved alongside the model (used in v4 pipeline)
SCALER_PATH = MODEL_DIR / "scaler.pkl"

# JSON file storing metadata about the last training run
# (feature list, training date, sample count, contamination, etc.)
MODEL_META_PATH = MODEL_DIR / "model_meta.json"

# Ensure the models directory exists when this module is imported
MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ── ML Features ───────────────────────────────────────────────────────────────
# Ordered list of feature names fed into the model.
# v3 used only the first 3; v4 will use all 5.
# The order here must match the column order used during training.
FEATURE_NAMES = [
    "syn_recv",           # Half-open TCP connections (SYN sent, no ACK yet)
    "established",        # Fully established TCP connections
    "total_connections",  # Total TCP connections (all states)
    "bytes_sent_per_sec", # Outbound throughput in bytes/second
    "bytes_recv_per_sec", # Inbound throughput in bytes/second
]

# Subset of FEATURE_NAMES used by the current v3 model.
# Referenced during the transition so v3 code can stay working
# while v4 training is being built.
V3_FEATURE_NAMES = [
    "syn_recv",
    "established",
    "total_connections",
]


# ── Model Hyperparameters ──────────────────────────────────────────────────────
# Fraction of training samples expected to be anomalies.
# 0.05 = 5% contamination assumption (matches current train.py).
CONTAMINATION = 0.05

# Random seed for reproducibility across train / retrain runs.
RANDOM_STATE = 42

# Number of trees in the Isolation Forest ensemble.
N_ESTIMATORS = 100


# ── Detection Thresholds ───────────────────────────────────────────────────────
# Isolation Forest decision_function() returns a score where:
#   positive  → more normal (further from anomaly boundary)
#   negative  → more anomalous (closer to / past boundary)
#
# These thresholds map the raw score to a human-readable
# confidence level shown in the dashboard.
#
# SCORE >= CONFIDENCE_LOW_THRESHOLD   → LOW confidence anomaly
# SCORE >= CONFIDENCE_HIGH_THRESHOLD  → MEDIUM confidence anomaly
# SCORE <  CONFIDENCE_HIGH_THRESHOLD  → HIGH confidence anomaly
#
# Values are intentionally conservative — do not tighten until
# the v4 model is trained on real baseline data.
CONFIDENCE_LOW_THRESHOLD  = -0.05   # just past the decision boundary
CONFIDENCE_HIGH_THRESHOLD = -0.15   # clearly anomalous score


# ── Risk Level Mapping ─────────────────────────────────────────────────────────
# Maps detection status to a risk label shown in the dashboard.
# Kept as a dict so the dashboard and engine both use the same labels
# without duplicating the mapping logic.
RISK_LEVELS = {
    "ANOMALY":  "HIGH",
    "COOLDOWN": "LOW",
    "NORMAL":   "LOW",
}

# Score below zero but model still predicts NORMAL → MEDIUM risk.
# This threshold matches the existing risk_level() logic in app.py.
MEDIUM_RISK_SCORE_THRESHOLD = 0.0


# ── Cooldown ───────────────────────────────────────────────────────────────────
# Number of consecutive NORMAL ticks required after an attack
# before the cooldown state is cleared and alerts resume.
# Raised from 5 (v3) to 10 (v4) to reduce post-attack false positives
# caused by TCP TIME_WAIT connections draining slowly.
ANOMALY_COOLDOWN_TICKS = 10


# ── Auto-Block ─────────────────────────────────────────────────────────────────
# Default number of anomaly triggers from the same IP before it
# is automatically added to the block list.
AUTO_BLOCK_THRESHOLD = 10

# Maximum number of IPs tracked in the in-memory anomaly counter
# before the oldest entries are evicted (memory leak prevention).
IP_ANOMALY_MAX_KEYS = 1000


# ── Monitoring / Push Loop ─────────────────────────────────────────────────────
# Seconds between each WebSocket push to connected dashboard clients.
PUSH_INTERVAL = 1.0

# Maximum number of recent events kept in the in-memory deque
# (separate from the SQLite database which stores everything).
EVENTS_DEQUE_SIZE = 100

# Number of recent events sent to the dashboard per push.
EVENTS_DISPLAY_LIMIT = 15

# Number of attack log rows sent to the dashboard per push.
ATTACK_LOG_DISPLAY_LIMIT = 20

# Maximum number of top source IPs shown in the IP Manager panel.
TOP_SOURCES_LIMIT = 8

# Maximum number of connection history ticks kept per IP.
IP_HISTORY_TICKS = 60


# ── Network Monitoring ─────────────────────────────────────────────────────────
# Divisor used to convert raw bytes/sec to a 0–100 network usage
# percentage shown in the dashboard gauge.
# 100_000 bytes/sec = 100 KB/s → maps to 100% on the gauge.
NETWORK_GAUGE_DIVISOR = 100_000

# Bytes/sec threshold above which traffic is classified as
# a Bandwidth Flood attack type.
BANDWIDTH_FLOOD_THRESHOLD = 5_000_000   # 5 MB/s

# Connection velocity (conns/sec) threshold for HTTP Flood classification.
HTTP_FLOOD_VELOCITY_THRESHOLD = 15

# SYN_RECV count threshold for SYN Flood classification.
SYN_FLOOD_THRESHOLD = 20

# Established connection count + low velocity → Slowloris classification.
SLOWLORIS_ESTABLISHED_THRESHOLD = 80
SLOWLORIS_VELOCITY_MAX          = 2

# Total connections + low SYN → Connection Exhaustion classification.
CONN_EXHAUSTION_TOTAL_THRESHOLD = 100
CONN_EXHAUSTION_SYN_MAX         = 5


# ── Simulator ──────────────────────────────────────────────────────────────────
# Default target for the attack simulator.
SIMULATOR_HOST = "127.0.0.1"
SIMULATOR_PORT = 8000

# Default auto-stop timeout in seconds if --timeout is not specified.
SIMULATOR_DEFAULT_TIMEOUT = 120

SIMULATOR_INTENSITY = {
    "low":    {"conns": 20,  "threads": 2,  "delay": 0.5},
    "medium": {"conns": 60,  "threads": 5,  "delay": 0.1},
    "high":   {"conns": 150, "threads": 10, "delay": 0.02},
}


# ── Baseline Collection ────────────────────────────────────────────────────────
# Duration in seconds for collect_baseline.py to run.
BASELINE_COLLECTION_DURATION = 180   # 3 minutes


# ── Database ───────────────────────────────────────────────────────────────────
DB_FILE = BASE_DIR / "sentinel.db"

# Maximum number of attack log rows returned by a single API call.
ATTACK_LOG_API_MAX = 1000
