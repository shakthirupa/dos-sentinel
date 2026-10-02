"""
DoS Sentinel v4.0 — Detection Engine
=====================================
Isolates all ML inference and rule-based classification from app.py.

Responsibilities:
  - Load and validate v4 model artifacts (IsolationForest + StandardScaler)
  - Run the inference pipeline: scale → predict → score
  - Classify attack pattern via rule-based heuristics (NOT ML)
  - Manage post-anomaly cooldown state
  - Return structured result dicts

NOT responsible for:
  - Collecting network traffic  (collector → engine)
  - Database / persistence      (database.py)
  - WebSocket / HTTP            (app.py)
"""

import json
import logging
import math

import joblib
import pandas as pd

from config import (
    ANOMALY_COOLDOWN_TICKS,
    BANDWIDTH_FLOOD_THRESHOLD,
    CONFIDENCE_HIGH_THRESHOLD,
    CONFIDENCE_LOW_THRESHOLD,
    CONN_EXHAUSTION_SYN_MAX,
    CONN_EXHAUSTION_TOTAL_THRESHOLD,
    FEATURE_NAMES,
    HTTP_FLOOD_VELOCITY_THRESHOLD,
    MEDIUM_RISK_SCORE_THRESHOLD,
    MODEL_META_PATH,
    MODEL_PATH,
    RISK_LEVELS,
    SCALER_PATH,
    SLOWLORIS_ESTABLISHED_THRESHOLD,
    SLOWLORIS_VELOCITY_MAX,
    SYN_FLOOD_THRESHOLD,
)

log = logging.getLogger(__name__)


class DetectionEngine:
    """
    Loads v4 model artifacts once and exposes a single predict() method.
    Maintains cooldown state internally — no global variables required.
    """

    def __init__(self):
        self._model, self._scaler, self._meta = self._load_artifacts()
        self._validate_features()

        # Cooldown state
        self._in_cooldown      = False
        self._cooldown_counter = 0

        log.info(
            "DetectionEngine ready — model %s, features %s",
            self._meta.get("model_version", "unknown"),
            self._meta.get("features"),
        )

    # ── Artifact loading ───────────────────────────────────────────────────────

    def _load_artifacts(self):
        missing = [p for p in (MODEL_PATH, SCALER_PATH, MODEL_META_PATH) if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "v4 model artifacts not found: "
                + ", ".join(str(p) for p in missing)
                + "\nRun: python train.py"
            )

        model  = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        with open(MODEL_META_PATH, "r") as f:
            meta = json.load(f)

        log.info("Loaded model from %s", MODEL_PATH)
        return model, scaler, meta

    def _validate_features(self):
        meta_features = self._meta.get("features", [])
        if meta_features != FEATURE_NAMES:
            raise ValueError(
                f"Feature mismatch.\n"
                f"  config.py : {FEATURE_NAMES}\n"
                f"  model_meta: {meta_features}"
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def predict(self, traffic: dict) -> dict:
        """
        Run the full detection pipeline on a single traffic snapshot.

        Required keys in `traffic`:
            syn_recv, established, total_connections,
            bytes_sent_per_sec, bytes_recv_per_sec

        Optional keys used only by rule-based classifier:
            conn_velocity   (float, connections/sec)

        Returns a structured result dict.
        """
        self._validate_input(traffic)

        # ── ML pipeline ───────────────────────────────────────────────────────
        df     = pd.DataFrame([{f: traffic[f] for f in FEATURE_NAMES}])
        scaled = self._scaler.transform(df)
        pred   = self._model.predict(scaled)[0]          # 1 = normal, -1 = anomaly
        score  = float(self._model.decision_function(scaled)[0])

        raw_detection = "ANOMALY" if pred == -1 else "NORMAL"

        # ── Cooldown ──────────────────────────────────────────────────────────
        detection = self._apply_cooldown(raw_detection)

        # ── Derived fields ────────────────────────────────────────────────────
        confidence  = self._confidence(score, detection)
        risk        = self._risk(detection, score)
        attack_type, attack_source = self._classify_attack(traffic, detection)

        return {
            "detection":          detection,
            "score":              round(score, 4),
            "confidence":         confidence,
            "risk":               risk,
            "attack_type":        attack_type,
            "attack_type_source": attack_source,
            "features":           {f: traffic[f] for f in FEATURE_NAMES},
            "model_version":      self._meta.get("model_version", "unknown"),
        }

    @property
    def in_cooldown(self) -> bool:
        return self._in_cooldown

    def reset_cooldown(self):
        """Force-clear cooldown state (useful in tests)."""
        self._in_cooldown      = False
        self._cooldown_counter = 0

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _validate_input(self, traffic: dict):
        for f in FEATURE_NAMES:
            if f not in traffic:
                raise KeyError(f"Missing required feature: '{f}'")
            v = traffic[f]
            if not isinstance(v, (int, float)):
                raise TypeError(f"Feature '{f}' must be numeric, got {type(v).__name__}")
            if math.isnan(v):
                raise ValueError(f"Feature '{f}' is NaN")
            if math.isinf(v):
                raise ValueError(f"Feature '{f}' is infinite")

    def _apply_cooldown(self, raw_detection: str) -> str:
        if raw_detection == "ANOMALY":
            self._in_cooldown      = True
            self._cooldown_counter = 0
            return "ANOMALY"
        if self._in_cooldown:
            self._cooldown_counter += 1
            if self._cooldown_counter >= ANOMALY_COOLDOWN_TICKS:
                self._in_cooldown      = False
                self._cooldown_counter = 0
            else:
                return "COOLDOWN"
        return "NORMAL"

    def _confidence(self, score: float, detection: str) -> str:
        """
        Describes confidence/severity of the anomaly classification.
        Only meaningful when detection == ANOMALY or COOLDOWN.
        For NORMAL traffic, returns LOW (low anomaly confidence).
        """
        if detection == "NORMAL":
            return "LOW"
        if score >= CONFIDENCE_LOW_THRESHOLD:
            return "LOW"
        if score >= CONFIDENCE_HIGH_THRESHOLD:
            return "MEDIUM"
        return "HIGH"

    def _risk(self, detection: str, score: float) -> str:
        if detection in RISK_LEVELS:
            return RISK_LEVELS[detection]
        # NORMAL but score dipped below zero → borderline
        if score < MEDIUM_RISK_SCORE_THRESHOLD:
            return "MEDIUM"
        return "LOW"

    def _classify_attack(self, traffic: dict, detection: str) -> tuple[str, str]:
        """
        Rule-based attack pattern classification.
        Returns (attack_type, source_label).

        This is NOT ML — it uses hardcoded thresholds from config.py.
        Only runs when detection is ANOMALY; otherwise returns ('-', 'none').
        """
        if detection != "ANOMALY":
            return "-", "none"

        syn   = traffic["syn_recv"]
        est   = traffic["established"]
        total = traffic["total_connections"]
        bps   = traffic["bytes_recv_per_sec"] + traffic["bytes_sent_per_sec"]
        vel   = traffic.get("conn_velocity", 0.0)   # optional; 0 if not provided

        if syn > SYN_FLOOD_THRESHOLD:
            return "SYN Flood", "rule_based"
        if bps > BANDWIDTH_FLOOD_THRESHOLD:
            return "Bandwidth Flood", "rule_based"
        if vel > HTTP_FLOOD_VELOCITY_THRESHOLD:
            return "HTTP Flood", "rule_based"
        if est > SLOWLORIS_ESTABLISHED_THRESHOLD and vel < SLOWLORIS_VELOCITY_MAX:
            return "Slowloris", "rule_based"
        if total > CONN_EXHAUSTION_TOTAL_THRESHOLD and syn < CONN_EXHAUSTION_SYN_MAX:
            return "Connection Exhaustion", "rule_based"

        return "Unclassified Anomaly", "rule_based"
