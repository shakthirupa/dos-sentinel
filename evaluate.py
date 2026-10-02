"""
DoS Sentinel v4.0 — Model Evaluation
======================================
Evaluates the v4 IsolationForest against test_data.csv.

Usage:
    python evaluate.py
    python evaluate.py --no-plots

IMPORTANT — Honest evaluation caveats
--------------------------------------
Isolation Forest is an UNSUPERVISED anomaly detector.
It was trained without labels.  Any labeled metrics below are
computed against the test labels supplied in test_data.csv and
reflect performance on that specific synthetic dataset only.

They do NOT establish real-world DoS detection capability.
"""

import argparse
import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from config import (
    FEATURE_NAMES,
    MODEL_META_PATH,
    MODEL_PATH,
    SCALER_PATH,
)
from engine import DetectionEngine

warnings.filterwarnings("ignore")

TEST_DATA_PATH = Path("test_data.csv")
REPORTS_DIR    = Path("reports")

# Columns in test_data.csv that hold cumulative byte counters
# (same format as traffic_data.csv — must be diff()'d to get per-sec rates)
_RAW_BYTE_COLS = ["bytes_sent", "bytes_received"]
_RATE_MAP      = {
    "bytes_sent":     "bytes_sent_per_sec",
    "bytes_received": "bytes_recv_per_sec",
}


# ── Artifact loading ───────────────────────────────────────────────────────────

def load_artifacts() -> tuple:
    """Load and validate v4 model artifacts. Exits on failure."""
    missing = [p for p in (MODEL_PATH, SCALER_PATH, MODEL_META_PATH) if not p.exists()]
    if missing:
        print(f"[ERROR] Missing artifacts: {[str(p) for p in missing]}")
        print("  Run: python train.py")
        sys.exit(1)

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(MODEL_META_PATH) as f:
        meta = json.load(f)

    if meta.get("features") != FEATURE_NAMES:
        print("[ERROR] Feature mismatch between model_meta.json and config.FEATURE_NAMES")
        print(f"  meta   : {meta.get('features')}")
        print(f"  config : {FEATURE_NAMES}")
        sys.exit(1)

    return model, scaler, meta


# ── Dataset loading ────────────────────────────────────────────────────────────

def load_test_data() -> tuple[pd.DataFrame, pd.Series | None, pd.DataFrame]:
    """
    Load test_data.csv and adapt it to the v4 feature set.

    test_data.csv format (detected at runtime):
        timestamp, syn_recv, established, total_connections,
        bytes_sent, bytes_received, label

    bytes_sent / bytes_received are cumulative OS counters.
    bytes_sent_per_sec / bytes_recv_per_sec are computed via diff(),
    same approach used in train.py.  Row 0 is dropped (no prior counter).

    Returns (X, labels) where labels may be None if no label column exists.
    """
    if not TEST_DATA_PATH.exists():
        print(f"[ERROR] {TEST_DATA_PATH} not found.")
        sys.exit(1)

    df = pd.read_csv(TEST_DATA_PATH)
    print(f"  Raw rows loaded  : {len(df)}")
    print(f"  Columns          : {list(df.columns)}")

    # ── Detect format ──────────────────────────────────────────────────────────
    has_rate_cols = all(f in df.columns for f in ["bytes_sent_per_sec", "bytes_recv_per_sec"])
    has_raw_cols  = all(c in df.columns for c in _RAW_BYTE_COLS)

    if not has_rate_cols and not has_raw_cols:
        print("[ERROR] test_data.csv has neither bytes_sent_per_sec/bytes_recv_per_sec "
              "nor bytes_sent/bytes_received columns.")
        print("  Cannot compute v4 features. Update test_data.csv to include these columns.")
        sys.exit(1)

    # ── Compute per-sec rates from cumulative counters ─────────────────────────
    if not has_rate_cols and has_raw_cols:
        print("  [INFO] bytes_sent/bytes_received are cumulative counters.")
        print("         Computing per-sec rates via diff() (same as train.py).")
        for raw_col, rate_col in _RATE_MAP.items():
            df[rate_col] = pd.to_numeric(df[raw_col], errors="coerce").diff()

        neg_sent = (df["bytes_sent_per_sec"] < 0).sum()
        neg_recv = (df["bytes_recv_per_sec"] < 0).sum()
        if neg_sent > 0 or neg_recv > 0:
            print(f"  [WARN] Negative byte diffs (sent={neg_sent}, recv={neg_recv}) "
                  f"— dropping (counter reset rows).")
            df = df[(df["bytes_sent_per_sec"] >= 0) & (df["bytes_recv_per_sec"] >= 0)]

        # Drop row 0 — NaN from diff() with no prior row
        df = df.dropna(subset=["bytes_sent_per_sec", "bytes_recv_per_sec"])
        df = df.reset_index(drop=True)
        print(f"  Rows after diff  : {len(df)}  (row 0 dropped — no prior counter)")

    # ── Validate all 5 features are now present ────────────────────────────────
    missing_feats = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing_feats:
        print(f"[ERROR] Still missing features after adaptation: {missing_feats}")
        sys.exit(1)

    # ── Numeric conversion + NaN/inf cleanup ──────────────────────────────────
    for feat in FEATURE_NAMES:
        df[feat] = pd.to_numeric(df[feat], errors="coerce")
    df[FEATURE_NAMES] = df[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
    bad = df[FEATURE_NAMES].isna().sum().sum()
    if bad > 0:
        print(f"  [WARN] {bad} NaN/inf values — dropping affected rows.")
        df = df.dropna(subset=FEATURE_NAMES)
        df = df.reset_index(drop=True)

    # ── Labels ────────────────────────────────────────────────────────────────
    labels = None
    if "label" in df.columns:
        # Align labels with the rows that survived diff() / dropna()
        raw_labels = df["label"].str.strip().str.lower()
        unique_vals = set(raw_labels.unique())
        if unique_vals <= {"normal", "anomaly"}:
            labels = (raw_labels == "anomaly").astype(int)
            print(f"  Labels found     : normal={( labels==0).sum()}  "
                  f"anomaly={(labels==1).sum()}")
        else:
            print(f"  [WARN] Unexpected label values {unique_vals} — ignoring labels.")

    X = df[FEATURE_NAMES].copy()
    return X, labels, df


# ── Engine consistency check ───────────────────────────────────────────────────

def check_engine_consistency(model, scaler, X: pd.DataFrame) -> None:
    """
    Verify that DetectionEngine uses the same scaler + model + feature order
    as this evaluation script by comparing predictions on the first row.
    """
    engine = DetectionEngine()
    row    = X.iloc[0].to_dict()

    # Direct pipeline
    scaled_direct = scaler.transform(pd.DataFrame([row], columns=FEATURE_NAMES))
    pred_direct   = model.predict(scaled_direct)[0]
    score_direct  = float(model.decision_function(scaled_direct)[0])

    # Via engine
    result = engine.predict(row)

    match = (
        result["score"] == round(score_direct, 4) and
        result["detection"] in ("NORMAL", "ANOMALY", "COOLDOWN")
    )
    print(f"  Direct pipeline  : pred={pred_direct:+d}  score={score_direct:+.4f}")
    print(f"  engine.predict() : detection={result['detection']}  "
          f"score={result['score']}  model_version={result['model_version']}")
    print(f"  Consistent       : {match}")
    if not match:
        print("  [WARN] Score mismatch — engine may have cooldown state active.")


# ── Plots ──────────────────────────────────────────────────────────────────────

def save_plots(scores: np.ndarray, preds: np.ndarray,
               labels: "pd.Series | None", meta: dict) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")   # non-interactive backend — no GUI window
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib not available — skipping plots.")
        return

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── 1. Score distribution ──────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 4))
    normal_scores  = scores[preds == 1]
    anomaly_scores = scores[preds == -1]
    ax.hist(normal_scores,  bins=20, alpha=0.7, label="Predicted Normal",  color="steelblue")
    ax.hist(anomaly_scores, bins=20, alpha=0.7, label="Predicted Anomaly", color="tomato")
    ax.axvline(0, color="black", linestyle="--", linewidth=1, label="Decision boundary (0)")
    ax.set_xlabel("Isolation Forest decision score")
    ax.set_ylabel("Count")
    ax.set_title(f"Score Distribution — {meta.get('model_version', 'v4')} "
                 f"({meta.get('baseline_type', 'mixed')} baseline)")
    ax.legend()
    fig.tight_layout()
    out = REPORTS_DIR / "score_distribution.png"
    fig.savefig(out, dpi=120)
    plt.close(fig)
    print(f"  Saved: {out}")

    # ── 2. Confusion matrix (only if labels exist) ────────────────────────────
    if labels is not None:
        y_pred_bin = (preds == -1).astype(int)
        cm = confusion_matrix(labels, y_pred_bin)
        fig, ax = plt.subplots(figsize=(4, 4))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        fig.colorbar(im, ax=ax)
        classes = ["Normal", "Anomaly"]
        ax.set_xticks([0, 1]); ax.set_xticklabels(classes)
        ax.set_yticks([0, 1]); ax.set_yticklabels(classes)
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        ax.set_title("Confusion Matrix (test_data.csv labels)")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black")
        fig.tight_layout()
        out = REPORTS_DIR / "confusion_matrix.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        print(f"  Saved: {out}")


# ── Main ───────────────────────────────────────────────────────────────────────

def evaluate(plots: bool = True) -> None:
    W = 52   # report width

    print()
    print("=" * W)
    print("  DoS Sentinel v4 — Model Evaluation")
    print("=" * W)

    # ── Load artifacts ────────────────────────────────────────────────────────
    print("\nLoading v4 artifacts...")
    model, scaler, meta = load_artifacts()
    print(f"  Model            : {MODEL_PATH}")
    print(f"  Scaler           : {SCALER_PATH}")
    print(f"  Metadata         : {MODEL_META_PATH}")

    # ── Load test data ────────────────────────────────────────────────────────
    print(f"\nLoading {TEST_DATA_PATH}...")
    X, labels, df_full = load_test_data()
    n_samples = len(X)

    if n_samples < 2:
        print(f"\n[ERROR] Only {n_samples} usable sample(s) after preprocessing.")
        print("  test_data.csv is too small for meaningful evaluation.")
        print("  Add more rows (at least 10 recommended) and re-run.")
        sys.exit(1)

    # ── Run inference ─────────────────────────────────────────────────────────
    X_scaled = scaler.transform(X)
    preds    = model.predict(X_scaled)          # +1 normal, -1 anomaly
    scores   = model.decision_function(X_scaled)

    n_normal  = (preds == 1).sum()
    n_anomaly = (preds == -1).sum()

    # ── Engine consistency ────────────────────────────────────────────────────
    print("\nEngine consistency check:")
    check_engine_consistency(model, scaler, X)

    # ── Report ────────────────────────────────────────────────────────────────
    print()
    print("=" * W)
    print("  EVALUATION REPORT")
    print("=" * W)

    print("\nModel:")
    print(f"  version          : {meta.get('model_version', 'unknown')}")
    print(f"  type             : {meta.get('model_type', 'unknown')}")
    print(f"  scaler           : {meta.get('scaler_type', 'unknown')}")
    print(f"  training samples : {meta.get('training_samples', 'unknown')}")
    print(f"  baseline type    : {meta.get('baseline_type', 'mixed (train.py)')}")
    print(f"  trained on       : {meta.get('source_dataset', 'unknown')}")

    print("\nFeatures (in order):")
    for i, f in enumerate(FEATURE_NAMES, 1):
        print(f"  {i}. {f}")

    print(f"\nDataset: {TEST_DATA_PATH}")
    print(f"  samples          : {n_samples}")
    print(f"  labelled         : {'yes' if labels is not None else 'no'}")
    if n_samples < 30:
        print(f"  [NOTE] Only {n_samples} samples — metrics are illustrative only.")
        print("         Add more rows to test_data.csv for reliable evaluation.")

    print("\nPrediction summary:")
    print(f"  predicted normal : {n_normal}  ({n_normal/n_samples*100:.1f}%)")
    print(f"  predicted anomaly: {n_anomaly}  ({n_anomaly/n_samples*100:.1f}%)")
    print(f"  anomaly rate     : {n_anomaly/n_samples*100:.1f}%")

    print("\nDecision scores  (negative = more anomalous):")
    print(f"  min              : {scores.min():+.4f}")
    print(f"  max              : {scores.max():+.4f}")
    print(f"  mean             : {scores.mean():+.4f}")
    print(f"  median           : {float(np.median(scores)):+.4f}")
    print(f"  std              : {scores.std():.4f}")
    print()
    print("  Interpretation:")
    print("    score > 0  -> further from anomaly boundary (more normal)")
    print("    score < 0  -> closer to / past anomaly boundary (more anomalous)")
    print("    pred = +1  -> model labels as NORMAL")
    print("    pred = -1  -> model labels as ANOMALY")
    print("    score is NOT a probability or confidence percentage.")

    # ── Labeled metrics ───────────────────────────────────────────────────────
    if labels is not None:
        y_pred_bin = (preds == -1).astype(int)
        acc  = accuracy_score(labels, y_pred_bin)
        prec = precision_score(labels, y_pred_bin, zero_division=0)
        rec  = recall_score(labels, y_pred_bin, zero_division=0)
        f1   = f1_score(labels, y_pred_bin, zero_division=0)
        cm   = confusion_matrix(labels, y_pred_bin)

        print()
        print("-" * W)
        print("  Labeled metrics (against test_data.csv labels)")
        print("-" * W)
        print()
        print("  Confusion matrix:")
        print(f"                  Pred Normal  Pred Anomaly")
        print(f"  Actual Normal   {cm[0,0]:>11d}  {cm[0,1]:>12d}")
        print(f"  Actual Anomaly  {cm[1,0]:>11d}  {cm[1,1]:>12d}")
        print()
        print(f"  Accuracy         : {acc*100:.1f}%")
        print(f"  Precision        : {prec*100:.1f}%")
        print(f"  Recall           : {rec*100:.1f}%")
        print(f"  F1 Score         : {f1*100:.1f}%")
        print()
        print("  Classification report:")
        print(classification_report(
            labels, y_pred_bin,
            target_names=["Normal", "Anomaly"],
            zero_division=0,
        ))

    # ── Caveats ───────────────────────────────────────────────────────────────
    print("-" * W)
    print("  IMPORTANT CAVEATS")
    print("-" * W)
    print()
    print("  1. Isolation Forest is UNSUPERVISED.")
    print("     It was trained without labels and learns what 'normal'")
    print("     looks like from the training distribution.")
    print()
    print("  2. Labeled metrics above are computed against synthetic")
    print("     test labels in test_data.csv.  They do NOT establish")
    print("     real-world DoS detection performance.")
    print()
    print("  3. The training dataset (traffic_data.csv) contains mixed")
    print("     normal + synthetic attack samples.  For a cleaner model,")
    print("     run: python collect_baseline.py && python retrain.py")
    print()
    print("  4. Attack type classification is rule-based (engine.py),")
    print("     not produced by the Isolation Forest.")
    print()
    if n_samples < 30:
        print(f"  5. test_data.csv has only {n_samples} rows.  Metrics are")
        print("     illustrative.  Expand the dataset for reliable evaluation.")
        print()

    # ── Plots ─────────────────────────────────────────────────────────────────
    if plots:
        print("Saving plots...")
        save_plots(scores, preds, labels, meta)

    print()
    print("=" * W)
    print("  Evaluation complete.")
    print("=" * W)
    print()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--no-plots", action="store_true", help="Skip matplotlib output")
    args = p.parse_args()
    evaluate(plots=not args.no_plots)
