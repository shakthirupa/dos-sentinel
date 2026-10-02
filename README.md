# DoS Sentinel v4

A real-time network anomaly detection and monitoring platform built with an Isolation Forest ML model, Flask-SocketIO backend, and a live browser dashboard.

> **Scope:** DoS Sentinel is a local demonstration and learning tool. It detects statistical anomalies in TCP connection patterns on the local machine. It is not a production-grade intrusion detection system and has not been validated against real-world attack traffic.

---

## Architecture

```
psutil (network collector)
        │
        ▼
  app.py  ──────────────────────────────────────────────────────┐
  get_network_data()                                             │
        │                                                        │
        ▼                                                        │
  engine.py — DetectionEngine                                    │
  ┌─────────────────────────────────────────────────────────┐   │
  │  1. Validate 5 input features                           │   │
  │  2. StandardScaler.transform()                          │   │
  │  3. IsolationForest.predict() + decision_function()     │   │
  │  4. Cooldown state machine (NORMAL / ANOMALY / COOLDOWN)│   │
  │  5. Rule-based attack classifier (engine.py)            │   │
  └─────────────────────────────────────────────────────────┘   │
        │                                                        │
        ▼                                                        │
  database.py — SQLite (WAL mode)                                │
  events table + blocked_ips table                               │
        │                                                        │
        └──────────────────────────────────────────────────────▶│
                                                                 │
  server.py (port 8000) ──── HTTP telemetry ──────────────────▶ │
                                                                 │
  app.py — WebSocket push (1 s interval) ──────────────────────▶│
                                                          dashboard
                                                    (browser, port 5000)
```

---

## ML Pipeline

- **Model:** Isolation Forest (`scikit-learn`)
- **Preprocessing:** StandardScaler — all 5 features are scaled before inference
- **Training data:** `traffic_data.csv` — 8 500 rows of synthetic traffic (mixed normal + attack samples)
- **Contamination:** 5% (hyperparameter in `config.py`)
- **Artifacts:** `models/isolation_forest.pkl`, `models/scaler.pkl`, `models/model_meta.json`

### Five ML Features

| Feature | Description |
|---|---|
| `syn_recv` | Half-open TCP connections (SYN sent, no ACK yet) |
| `established` | Fully established TCP connections |
| `total_connections` | Total TCP connections (all states) |
| `bytes_sent_per_sec` | Outbound throughput in bytes/second |
| `bytes_recv_per_sec` | Inbound throughput in bytes/second |

### Detection States

| State | Meaning |
|---|---|
| `NORMAL` | Traffic within the learned normal boundary |
| `ANOMALY` | Isolation Forest flagged the snapshot as anomalous |
| `COOLDOWN` | Post-anomaly settling period (10 ticks by default) — suppresses repeated alerts while TCP TIME_WAIT connections drain |

### Rule-Based Attack Classification

Attack type labels (SYN Flood, HTTP Flood, Bandwidth Flood, Slowloris, Connection Exhaustion) are assigned by threshold rules in `engine.py` — **not** by the Isolation Forest. The ML model only decides normal vs. anomaly. The rule classifier runs only when `detection == ANOMALY`.

### Anomaly Score

The dashboard displays the raw `decision_function()` score from the Isolation Forest:
- Positive → further from the anomaly boundary (more normal)
- Negative → closer to / past the anomaly boundary (more anomalous)
- **This is not a probability or a percentage.**

---

## Features

- Live TCP/network monitoring via `psutil`
- Isolation Forest anomaly detection with StandardScaler preprocessing
- Rule-based attack type classification (5 attack patterns)
- Post-anomaly cooldown state to reduce false positives
- Auto-blocking of repeat-offending source IPs
- SQLite persistence (WAL mode) for events and blocked IPs
- HTTP telemetry from the protected server (request rate, status codes, response time)
- Real-time WebSocket dashboard — charts, gauges, IP manager, attack log
- Built-in attack simulator for controlled local testing
- Baseline collection and retraining workflow for machine-specific models
- Model evaluation script with honest caveats

---

## Requirements

- Python 3.8+
- Windows (run `app.py` as **Administrator** — required for `psutil.net_connections`)

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the v4 model (uses traffic_data.csv)
python train.py
```

This produces `models/isolation_forest.pkl`, `models/scaler.pkl`, and `models/model_meta.json`.

---

## Running

**Terminal 1 — Protected target server**
```bash
python server.py
```

**Terminal 2 — Dashboard** (run as Administrator on Windows)
```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Simulating an Attack

**From the dashboard** — use the Simulator tab.

**From the command line:**
```bash
python simulator.py --attack syn --intensity high --timeout 60
```

Options:
- `--attack`: `syn`, `http`, `slowloris`, `exhaust`
- `--intensity`: `low`, `medium`, `high`
- `--timeout`: seconds before auto-stop (default: 120)

> The simulator targets `127.0.0.1:8000` only. It does not send traffic to any external host.

---

## Baseline Collection and Retraining

The default model is trained on `traffic_data.csv`, which contains synthetic data. For a model calibrated to your machine's normal traffic:

```bash
# 1. Collect 3 minutes of normal traffic (no attacks running)
python collect_baseline.py

# 2. Retrain on the collected baseline
python retrain.py
```

The retrained model is saved atomically — the old model is only replaced after the new one passes validation.

---

## Model Evaluation

```bash
python evaluate.py
python evaluate.py --no-plots   # skip matplotlib output
```

Evaluates the v4 model against `test_data.csv` and prints a report including prediction summary, decision score statistics, and (if labels are present) accuracy/precision/recall/F1.

> **Important:** Labeled metrics are computed against synthetic test labels in `test_data.csv`. They reflect performance on that specific dataset only and do not establish real-world DoS detection capability.

---

## Environment Variables

Copy `.env.example` to `.env` and set:

```
SECRET_KEY=your-secret-key-here
```

If not set, a random key is generated on each startup (sessions will not persist across restarts).

---

## Project Structure

```
dos-demmo/
├── app.py                  # Flask + SocketIO backend, network collector, push loop
├── engine.py               # DetectionEngine — ML inference + rule-based classifier
├── database.py             # SQLite persistence layer
├── server.py               # Protected target HTTP server (port 8000)
├── simulator.py            # Attack simulator (localhost only)
├── config.py               # Central configuration — all constants
├── train.py                # Train v4 model on traffic_data.csv
├── retrain.py              # Retrain on clean normal-only baseline
├── collect_baseline.py     # Collect normal traffic baseline
├── evaluate.py             # Evaluate model against test_data.csv
├── traffic_data.csv        # 8 500-row synthetic training dataset
├── test_data.csv           # Labeled test dataset for evaluate.py
├── requirements.txt
├── .env.example
├── models/
│   └── model_meta.json     # Training metadata (committed as reference)
│   # isolation_forest.pkl and scaler.pkl are gitignored — regenerate with train.py
├── data/
│   # normal_baseline.csv is gitignored — generated by collect_baseline.py
├── reports/
│   # confusion_matrix.png and score_distribution.png are gitignored — generated by evaluate.py
├── static/
│   ├── dashboard.js
│   └── style.css
├── templates/
│   └── dashboard.html
└── legacy/
    # v3 prototype scripts — not used by the v4 application
    # See legacy/README.md
```

---

## Limitations

- **Synthetic training data:** `traffic_data.csv` was generated programmatically. The model's normal boundary reflects that synthetic distribution, not real-world traffic. Use `collect_baseline.py` + `retrain.py` for a machine-specific model.
- **Localhost only:** The system monitors the local machine's TCP stack. It does not inspect network packets or monitor remote hosts.
- **Windows Administrator required:** `psutil.net_connections()` requires elevated privileges on Windows. On Linux/macOS this restriction may not apply.
- **Unsupervised model:** Isolation Forest learns what "normal" looks like from training data. It has no concept of specific attack signatures. The attack type labels come from rule-based thresholds, not from the ML model.
- **Not production-ready:** This is a demonstration and learning platform. It should not be used as a primary security control.
- **Eventlet deprecation:** Flask-SocketIO has deprecated Eventlet as an async transport. The current implementation uses Eventlet and will display a deprecation warning at startup. Migration to an alternative transport is planned as a separate step.
