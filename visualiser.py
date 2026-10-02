import pandas as pd
import matplotlib.pyplot as plt
import joblib

# Load dataset
data = pd.read_csv(
    "traffic_data.csv",
    header=None,
    names=[
        "timestamp",
        "syn_recv",
        "established",
        "total_connections",
        "bytes_sent",
        "bytes_received"
    ]
)

# Features used for ML
features = [
    "syn_recv",
    "established",
    "total_connections"
]

X = data[features]

# Load the trained model
model = joblib.load("dos_model.pkl")

# Predict
data["prediction"] = model.predict(X)

# Separate normal and anomaly
normal = data[data["prediction"] == 1]
anomaly = data[data["prediction"] == -1]

print("Total observations:", len(data))
print("Normal:", len(normal))
print("Anomalies:", len(anomaly))

# Create graph
plt.figure(figsize=(14, 7))

# Normal traffic
plt.plot(
    data.index,
    data["syn_recv"],
    label="SYN_RECV"
)

# Highlight anomalies
plt.scatter(
    anomaly.index,
    anomaly["syn_recv"],
    label="Detected Anomaly",
    s=25
)

plt.xlabel("Observation")
plt.ylabel("SYN_RECV Connections")

plt.title("DoS Traffic Analysis using Isolation Forest")

plt.legend()
plt.grid(True)

plt.tight_layout()
plt.show()