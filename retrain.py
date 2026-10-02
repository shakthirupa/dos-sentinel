import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

df = pd.read_csv("real_baseline.csv")
print(f"Loaded {len(df)} samples")
print(df[["syn_recv", "established", "total_connections"]].describe())

X = df[["syn_recv", "established", "total_connections"]]

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X)

joblib.dump(model, "dos_model.pkl")
print("\nModel retrained and saved as dos_model.pkl")
print(f"  syn_recv range:         {X.syn_recv.min()} – {X.syn_recv.max()}")
print(f"  established range:      {X.established.min()} – {X.established.max()}")
print(f"  total_connections range:{X.total_connections.min()} – {X.total_connections.max()}")
