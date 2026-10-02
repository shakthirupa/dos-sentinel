# Legacy — v3 Prototypes

These files are the original v3 proof-of-concept scripts that preceded the v4 architecture.
They are kept here for reference only and are **not used by the v4 application**.

| File | Description |
|---|---|
| `detector.py` | Standalone v3 detector. Loads `dos_model.pkl` directly, uses only 3 features (syn_recv, established, total_connections), prints to terminal. Superseded by `engine.py` + `app.py`. |
| `monitor.py` | 14-line SYN_RECV counter. Prints live SYN count to terminal. Superseded by `app.py`'s `get_network_data()`. |
| `visualiser.py` | Loads `dos_model.pkl`, runs predictions on `traffic_data.csv` with 3 v3 features, plots SYN_RECV with anomaly scatter using matplotlib. Superseded by `evaluate.py` and the live dashboard. |
| `local_test.py` | Opens 50 raw TCP connections to `127.0.0.1:8000` and holds them for 10 seconds. Used during early development to manually trigger connection count spikes. |

None of these files import from `config.py`, `engine.py`, or `database.py`.
`dos_model.pkl` (the v3 model binary they depended on) has been deleted — regenerate with `python train.py` if needed for historical reference.
