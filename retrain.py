"""
DoS Sentinel v4.0 — Retrain on Normal Baseline
================================================
Retrains the v4 IsolationForest + StandardScaler using a clean,
normal-only baseline collected by collect_baseline.py.

Pipeline:
    Load CSV  →  Validate  →  Scale  →  Train  →  Sanity-test
    →  Save to temp paths  →  Validate reload  →  Promote to production

Usage:
    python retrain.py
    python retrain.py --input data/normal_baseline.csv
    python retrain.py --input data/normal_baseline.csv --min-samples 50

IMPORTANT:
    Isolation Forest is an unsupervised anomaly detector.
    It learns what "normal" looks like from this dataset.
    It does NOT learn to classify DoS attack types.
    Attack classification is handled separately by rule-based logic in engine.py.
"""

import argparse
import json
import shutil
import sys
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import (
    CONTAMINATION,
    FEATURE_NAMES,
    MODEL_META_PATH,
    MODEL_PATH,
    N_ESTIMATORS,
    RANDOM_STATE,
    SCALER_PATH,
    V3_FEATURE_NAMES,   # retained for historical metadata only — not used at v4 inference
)

warnings.filterwarnings("ignore")

DEFAULT_INPUT   = Path("data") / "normal_baseline.csv"
DEFAULT_MIN_SAMPLES = 30
EXPECTED_HEADER = ["timestamp", "syn_recv", "established", "total_connections",
                   "bytes_sent_per_sec", "bytes_recv_per_sec"]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Retrain DoS Sentinel v4 on a normal-only baseline")
    p.add_argument("--input",       type=Path, default=DEFAULT_INPUT,
                   help=f"Baseline CSV path (default: {DEFAULT_INPUT})")
    p.add_argument("--min-samples", type=int,  default=DEFAULT_MIN_SAMPLES,
                   help=f"Minimum rows required (default: {DEFAULT_MIN_SAMPLES})")
    return p.parse_args()


# ── Validation ─────────────────────────────────────────────────────────────────

def _load_and_validate(path: Path, min_samples: int) -> pd.DataFrame:
    if not path.exists():
        print(f"[ERROR] Input file not found: {path}")
        print(f"  Run: python collect_baseline.py --output {path}")
        sys.exit(1)

    df = pd.read_csv(path)

    # Header check
    missing_cols = [c for c in EXPECTED_HEADER if c not in df.columns]
    if missing_cols:
        print(f"[ERROR] Missing columns: {missing_cols}")
        print(f"  Expected: {EXPECTED_HEADER}")
        sys.exit(1)

    # Feature columns must be numeric
    for feat in FEATURE_NAMES:
        df[feat] = pd.to_numeric(df[feat], errors="coerce")

    nan_count = df[FEATURE_NAMES].isna().sum().sum()
    if nan_count > 0:
        print(f"  [WARN] {nan_count} non-numeric feature values — dropping affected rows.")
        df = df.dropna(subset=FEATURE_NAMES)

    # Replace inf
    df[FEATURE_NAMES] = df[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
    inf_count = df[FEATURE_NAMES].isna().sum().sum()
    if inf_count > 0:
        print(f"  [WARN] {inf_count} inf values — dropping affected rows.")
        df = df.dropna(subset=FEATURE_NAMES)

    # Drop negative byte rates (counter reset artefacts)
    neg_mask = (df["bytes_sent_per_sec"] < 0) | (df["bytes_recv_per_sec"] < 0)
    if neg_mask.sum() > 0:
        print(f"  [WARN] {neg_mask.sum()} rows with negative byte rates — dropping.")
        df = df[~neg_mask]

    df = df.reset_index(drop=True)

    if len(df) < min_samples:
        print(f"[ERROR] Only {len(df)} valid samples after cleaning "
              f"(need at least {min_samples}).")
        print(f"  Run collect_baseline.py for longer to gather more data.")
        sys.exit(1)

    return df


# ── Sanity test ────────────────────────────────────────────────────────────────

def _sanity_test(model: IsolationForest, scaler: StandardScaler) -> bool:
    """
    Quick smoke-test on two synthetic vectors.
    Returns True if the model behaves as expected (normal → 1, unusual → -1).

    NOTE: This is a heuristic check only. The unusual vector uses extreme
    values that should be far outside any normal baseline. It does NOT
    validate real-world DoS detection accuracy.
    """
    normal_vec = pd.DataFrame([{
        "syn_recv": 0, "established": 25, "total_connections": 50,
        "bytes_sent_per_sec": 100_000, "bytes_recv_per_sec": 150_000,
    }], columns=FEATURE_NAMES)

    unusual_vec = pd.DataFrame([{
        "syn_recv": 200, "established": 800, "total_connections": 1500,
        "bytes_sent_per_sec": 50_000_000, "bytes_recv_per_sec": 60_000_000,
    }], columns=FEATURE_NAMES)

    n_pred = model.predict(scaler.transform(normal_vec))[0]
    u_pred = model.predict(scaler.transform(unusual_vec))[0]
    n_score = float(model.decision_function(scaler.transform(normal_vec))[0])
    u_score = float(model.decision_function(scaler.transform(unusual_vec))[0])

    print(f"  Normal vector  -> pred={n_pred:+d}  score={n_score:+.4f}"
          f"  ({'NORMAL' if n_pred == 1 else 'ANOMALY'})")
    print(f"  Unusual vector -> pred={u_pred:+d}  score={u_score:+.4f}"
          f"  ({'NORMAL' if u_pred == 1 else 'ANOMALY'})")
    print()
    print("  NOTE: 'Unusual' here means extreme synthetic values, not a")
    print("  confirmed DoS attack. Attack classification is rule-based (engine.py).")

    return u_pred == -1   # unusual vector should be flagged


# ── Main ───────────────────────────────────────────────────────────────────────

def retrain(input_path: Path, min_samples: int) -> None:
    print()
    print("=" * 50)
    print("  DoS Sentinel v4 — Retrain on Normal Baseline")
    print("=" * 50)
    print()

    # ── 1. Load + validate ────────────────────────────────────────────────────
    print(f"Loading {input_path}...")
    df = _load_and_validate(input_path, min_samples)
    print(f"  Valid samples : {len(df)}")
    print()

    X = df[FEATURE_NAMES].copy()

    # ── 2. Feature statistics ─────────────────────────────────────────────────
    print("Feature statistics (pre-scaling):")
    print("-" * 50)
    stats = X.describe().loc[["mean", "std", "min", "max"]]
    for feat in FEATURE_NAMES:
        print(f"  {feat:<25}  "
              f"mean={stats[feat]['mean']:>12.1f}  "
              f"std={stats[feat]['std']:>12.1f}  "
              f"min={stats[feat]['min']:>10.1f}  "
              f"max={stats[feat]['max']:>10.1f}")
    print()

    # ── 3. Scale ──────────────────────────────────────────────────────────────
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── 4. Train ──────────────────────────────────────────────────────────────
    print("Training Isolation Forest...")
    print(f"  n_estimators  = {N_ESTIMATORS}")
    print(f"  contamination = {CONTAMINATION}")
    print(f"  random_state  = {RANDOM_STATE}")
    print()

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
    )
    model.fit(X_scaled)

    preds     = model.predict(X_scaled)
    n_normal  = (preds == 1).sum()
    n_anomaly = (preds == -1).sum()
    print(f"  Self-labelled normal  : {n_normal}")
    print(f"  Self-labelled anomaly : {n_anomaly}  "
          f"(~{CONTAMINATION*100:.0f}% contamination assumption)")
    print()

    # ── 5. Sanity test ────────────────────────────────────────────────────────
    print("Sanity test:")
    passed = _sanity_test(model, scaler)
    print()
    if not passed:
        print("  [WARN] Unusual vector was NOT flagged as anomaly.")
        print("  The baseline may contain high-traffic samples that shifted")
        print("  the model's normal boundary. Consider collecting a quieter baseline.")
        print()

    # ── 6. Save to temp paths, then promote atomically ────────────────────────
    tmp_model  = MODEL_PATH.with_suffix(".tmp.pkl")
    tmp_scaler = SCALER_PATH.with_suffix(".tmp.pkl")
    tmp_meta   = MODEL_META_PATH.with_suffix(".tmp.json")

    joblib.dump(model,  tmp_model)
    joblib.dump(scaler, tmp_scaler)

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
        "source_dataset":     str(input_path),
        "baseline_type":      "normal_only",
        "dataset_note": (
            "Trained on clean normal-only baseline collected by collect_baseline.py. "
            "No synthetic attack samples included."
        ),
    }
    with open(tmp_meta, "w") as f:
        json.dump(meta, f, indent=2)

    # ── 7. Validate reload before promoting ───────────────────────────────────
    print("Validating artifacts before promoting...")
    try:
        check_model  = joblib.load(tmp_model)
        check_scaler = joblib.load(tmp_scaler)
        with open(tmp_meta) as f:
            check_meta = json.load(f)

        assert check_meta["features"] == FEATURE_NAMES, "Feature order mismatch"
        assert check_meta["baseline_type"] == "normal_only", "baseline_type missing"
        assert check_meta["model_version"] == "v4.0", "model_version missing"

        # Quick predict to confirm the loaded model works
        test_vec = pd.DataFrame([{f: 0 for f in FEATURE_NAMES}], columns=FEATURE_NAMES)
        check_model.predict(check_scaler.transform(test_vec))

        print("  Reload validation  : OK")
        print(f"  Feature order      : {check_meta['features']}")
        print(f"  baseline_type      : {check_meta['baseline_type']}")
        print(f"  model_version      : {check_meta['model_version']}")
        print()
    except Exception as e:
        tmp_model.unlink(missing_ok=True)
        tmp_scaler.unlink(missing_ok=True)
        tmp_meta.unlink(missing_ok=True)
        print(f"[ERROR] Artifact validation failed: {e}")
        print("  Production model was NOT replaced.")
        sys.exit(1)

    # ── 8. Promote (atomic rename) ────────────────────────────────────────────
    shutil.move(str(tmp_model),  str(MODEL_PATH))
    shutil.move(str(tmp_scaler), str(SCALER_PATH))
    shutil.move(str(tmp_meta),   str(MODEL_META_PATH))

    # ── 9. Summary ────────────────────────────────────────────────────────────
    print("=" * 50)
    print("  Retraining complete.")
    print("=" * 50)
    print(f"  Training samples : {len(df)}")
    print(f"  Model saved      : {MODEL_PATH}")
    print(f"  Scaler saved     : {SCALER_PATH}")
    print(f"  Metadata saved   : {MODEL_META_PATH}")
    print()
    print("  [NOTE] v3 dos_model.pkl has been removed; see legacy/README.md.")
    print("  [NOTE] traffic_data.csv was NOT modified.")
    print()


if __name__ == "__main__":
    args = _parse_args()
    retrain(args.input, args.min_samples)
