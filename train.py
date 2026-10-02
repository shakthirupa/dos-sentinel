import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

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

print("Dataset loaded!")
print(data.head())

features = [
    "syn_recv",
    "established",
    "total_connections"
]

X = data[features]

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(X)

predictions = model.predict(X)

data["prediction"] = predictions

normal = (predictions == 1).sum()
anomalies = (predictions == -1).sum()

print("\nTraining completed!")
print("Normal observations:", normal)
print("Anomalies detected:", anomalies)

joblib.dump(model, "dos_model.pkl")

print("\nModel saved as dos_model.pkl")