"""
DoS Sentinel v4.0 — Model Training Script
==========================================
Trains an Isolation Forest on traffic_data.csv using 5 features.
Saves:
  - models/isolation_forest.pkl  (trained model)
  - models/scaler.pkl            (fitted StandardScaler)
  - models/model_meta.json       (training metadata)

v3 dos_model.pkl has been removed; see legacy/README.md.
"""

import sys
import json
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import (
    FEATURE_NAMES,
    V3_FEATURE_NAMES,   # retained for historical metadata only — not used at v4 inference
    MODEL_PATH,
    SCALER_PATH,
    MODEL_META_PATH,
    CONTAMINATION,
    RANDOM_STATE,
    N_ESTIMATORS,
)

warnings.filterwarnings("ignore")

SOURCE_DATASET  = "traffic_data.csv"
RAW_COLUMNS     = ["timestamp", "syn_recv", "established",
                   "total_connections", "bytes_sent", "bytes_received"]
MIN_SAMPLES     = 100


# ── 1. Load ────────────────────────────────────────────────────────────────────

print()
print("=" * 46)
print("       DOS SENTINEL v4 TRAINING")
print("=" * 46)
print()
print(f"Loading {SOURCE_DATASET}...")

try:
    df = pd.read_csv(SOURCE_DATASET, header=None, names=RAW_COLUMNS)
except FileNotFoundError:
    print(f"[ERROR] {SOURCE_DATASET} not found.")
    sys.exit(1)

print(f"  Raw rows loaded : {len(df)}")


# ── 2. Validate required columns ───────────────────────────────────────────────

missing = [c for c in RAW_COLUMNS if c not in df.columns]
if missing:
    print(f"[ERROR] Missing columns: {missing}")
    sys.exit(1)


# ── 3. Parse timestamps ────────────────────────────────────────────────────────

df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
bad_ts = df["ts"].isna().sum()
if bad_ts > 0:
    print(f"  [WARN] {bad_ts} rows with unparseable timestamps — dropping.")
    df = df.dropna(subset=["ts"])

df = df.sort_values("ts").reset_index(drop=True)


# ── 4. Convert numeric columns ─────────────────────────────────────────────────

numeric_cols = ["syn_recv", "established", "total_connections",
                "bytes_sent", "bytes_received"]
for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

nan_before = df[numeric_cols].isna().sum().sum()
if nan_before > 0:
    print(f"  [WARN] {nan_before} non-numeric values found — dropping affected rows.")
    df = df.dropna(subset=numeric_cols)

df = df.reset_index(drop=True)


# ── 5. Compute bytes_per_sec from cumulative counters ─────────────────────────
#
# bytes_sent / bytes_received are cumulative OS network counters.
# elapsed between consecutive rows is always exactly 1 second
# (verified: std=0, min=max=1.0 across all 8500 rows).
# Therefore: diff() == per-second rate directly.
#
# Row 0 has no previous row — it is dropped (NaN after diff).

elapsed = df["ts"].diff().dt.total_seconds()

# Sanity check: warn if any gap is not 1 second
non_unit = (elapsed.dropna() != 1.0).sum()
if non_unit > 0:
    print(f"  [WARN] {non_unit} rows have elapsed != 1.0s — "
          f"bytes_per_sec values for those rows may be inaccurate.")

df["bytes_sent_per_sec"] = df["bytes_sent"].diff()
df["bytes_recv_per_sec"] = df["bytes_received"].diff()

# Drop row 0 (NaN from diff) and any rows with negative diffs
# (counter resets, e.g. OS reboot mid-capture)
df = df.dropna(subset=["bytes_sent_per_sec", "bytes_recv_per_sec"])

neg_sent = (df["bytes_sent_per_sec"] < 0).sum()
neg_recv = (df["bytes_recv_per_sec"] < 0).sum()
if neg_sent > 0 or neg_recv > 0:
    print(f"  [WARN] Negative byte diffs detected "
          f"(sent={neg_sent}, recv={neg_recv}) — dropping (counter reset rows).")
    df = df[
        (df["bytes_sent_per_sec"] >= 0) &
        (df["bytes_recv_per_sec"] >= 0)
    ]

df = df.reset_index(drop=True)


# ── 6. Check for inf / NaN in feature columns ─────────────────────────────────

df[FEATURE_NAMES] = df[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
inf_nan = df[FEATURE_NAMES].isna().sum().sum()
if inf_nan > 0:
    print(f"  [WARN] {inf_nan} inf/NaN values in features — dropping affected rows.")
    df = df.dropna(subset=FEATURE_NAMES)

df = df.reset_index(drop=True)


# ── 7. Dataset composition warning ────────────────────────────────────────────
#
# traffic_data.csv contains BOTH normal traffic (rows 0–1278, syn_recv=0,
# total_connections<=80) AND synthetic attack traffic (rows 1279+,
# syn_recv up to 69, total_connections up to 219).
#
# Isolation Forest is unsupervised — it does NOT use labels.
# However, training on a dataset that already contains attack samples
# means the model learns "attacks are somewhat normal" if contamination
# is set too low, or over-flags normal traffic if set too high.
#
# WARNING: For best results, retrain using collect_baseline.py + retrain.py
# to capture a clean normal-only baseline from your machine.

normal_rows = (df["syn_recv"] == 0).sum()
attack_rows = (df["syn_recv"] > 0).sum()
attack_pct  = attack_rows / len(df) * 100

print()
print("  [DATASET COMPOSITION WARNING]")
print(f"  Normal rows  (syn_recv=0) : {normal_rows}")
print(f"  Attack rows  (syn_recv>0) : {attack_rows} ({attack_pct:.1f}%)")
print(f"  The dataset contains synthetic attack samples mixed into training data.")
print(f"  The model will treat {CONTAMINATION*100:.0f}% of samples as anomalies.")
print(f"  For a cleaner model, run: python collect_baseline.py && python retrain.py")


# ── 8. Minimum sample check ────────────────────────────────────────────────────

print()
print(f"  Valid training samples : {len(df)}")

if len(df) < MIN_SAMPLES:
    print(f"[ERROR] Only {len(df)} valid samples — need at least {MIN_SAMPLES}. "
          f"Check {SOURCE_DATASET}.")
    sys.exit(1)


# ── 9. Feature matrix + statistics ────────────────────────────────────────────

X = df[FEATURE_NAMES].copy()

print()
print("Feature statistics (pre-scaling):")
print("-" * 46)
stats = X.describe().loc[["mean", "std", "min", "max"]]
for feat in FEATURE_NAMES:
    print(f"  {feat:<25} "
          f"mean={stats[feat]['mean']:>10.1f}  "
          f"std={stats[feat]['std']:>10.1f}  "
          f"min={stats[feat]['min']:>8.1f}  "
          f"max={stats[feat]['max']:>8.1f}")


# ── 10. Scale ──────────────────────────────────────────────────────────────────

scaler  = StandardScaler()
X_scaled = scaler.fit_transform(X)


# ── 11. Train ──────────────────────────────────────────────────────────────────

print()
print("Training Isolation Forest...")
print(f"  n_estimators  = {N_ESTIMATORS}")
print(f"  contamination = {CONTAMINATION}")
print(f"  random_state  = {RANDOM_STATE}")

model = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
)
model.fit(X_scaled)

preds     = model.predict(X_scaled)
n_normal  = (preds == 1).sum()
n_anomaly = (preds == -1).sum()
print(f"  Labelled normal  : {n_normal}")
print(f"  Labelled anomaly : {n_anomaly}")


# ── 12. Save artifacts ─────────────────────────────────────────────────────────

joblib.dump(model,  MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)

meta = {
    "model_version":      "v4.0",
    "model_type":         "IsolationForest",
    "scaler_type":        "StandardScaler",
    "features":           FEATURE_NAMES,
    "v3_features":        V3_FEATURE_NAMES,
    "training_samples":   int(len(df)),
    "n_estimators":       N_ESTIMATORS,
    "contamination":      CONTAMINATION,
    "random_state":       RANDOM_STATE,
    "training_timestamp": datetime.now().isoformat(),
    "source_dataset":     SOURCE_DATASET,
    "dataset_note": (
        "Dataset contains both normal and synthetic attack samples. "
        "Retrain on clean baseline for production use."
    ),
}

with open(MODEL_META_PATH, "w") as f:
    json.dump(meta, f, indent=2)


# ── 13. Summary ────────────────────────────────────────────────────────────────

print()
print("=" * 46)
print("       DOS SENTINEL v4 TRAINING")
print("=" * 46)
print()
print(f"Training samples : {len(df)}")
print()
print("Features:")
for feat in FEATURE_NAMES:
    print(f"  - {feat}")
print()
print("Scaler  : StandardScaler")
print("Model   : Isolation Forest")
print()
print(f"Model saved    : {MODEL_PATH}")
print(f"Scaler saved   : {SCALER_PATH}")
print(f"Metadata saved : {MODEL_META_PATH}")
print()
print("Training completed successfully.")
print()
print("[NOTE] v3 dos_model.pkl has been removed; see legacy/README.md.")
print()
