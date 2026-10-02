# DoS Sentinel

A real-time Denial-of-Service detection dashboard using an Isolation Forest ML model, Flask + WebSocket backend, and a live browser dashboard.

## Features

- Live traffic monitoring via `psutil`
- Isolation Forest anomaly detection
- Attack type classification (SYN Flood, HTTP Flood, Slowloris, Connection Exhaustion, Bandwidth Flood)
- Auto-blocking of repeat offenders
- SQLite persistence for events and blocked IPs
- Built-in attack simulator for testing
- Real-time dashboard with charts, gauges, and IP manager

## Requirements

- Python 3.8+
- Windows (run as **Administrator** for `psutil.net_connections`)

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model (uses traffic_data.csv)
python train.py

# 3. (Optional) Collect real baseline from your machine and retrain
python collect_baseline.py   # runs for 3 minutes
python retrain.py
```

## Running

**Terminal 1 — Target server**
```bash
python server.py
```

**Terminal 2 — Dashboard** (run as Administrator)
```bash
python app.py
```

Open `http://localhost:5000` in your browser.

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

## Environment Variables

Copy `.env.example` to `.env` and set:

```
SECRET_KEY=your-secret-key-here
```

If not set, a random key is generated on each startup (sessions won't persist across restarts).

## Project Structure

```
dos-demmo/
├── app.py              # Flask + SocketIO backend
├── database.py         # SQLite persistence layer
├── simulator.py        # Attack simulator
├── train.py            # Model training script
├── collect_baseline.py # Collect real baseline traffic
├── retrain.py          # Retrain model on real data
├── server.py           # Target HTTP server (port 8000)
├── traffic_data.csv    # Synthetic training data
├── requirements.txt
├── static/
│   ├── dashboard.js
│   └── style.css
└── templates/
    └── dashboard.html
```

## Notes

- `dos_model.pkl` and `sentinel.db` are excluded from git (regenerated locally)
- The model was trained on synthetic data with `total_connections` max ~80. If your machine has many more idle connections, retrain using `collect_baseline.py` + `retrain.py`
