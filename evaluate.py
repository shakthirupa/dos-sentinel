import pandas as pd
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Load test dataset
data = pd.read_csv("test_data.csv")

print("Test dataset loaded!")
print(data.head())

# Features used by the model
features = [
    "syn_recv",
    "established",
    "total_connections"
]

X_test = data[features]

# Load trained Isolation Forest model
model = joblib.load("dos_model.pkl")

# Model prediction
predictions = model.predict(X_test)

# Convert Isolation Forest output:
#  1  = normal
# -1  = anomaly
#
# Our test labels:
# 0 = normal
# 1 = anomaly

y_pred = (predictions == -1).astype(int)
y_test = (data["label"] == "anomaly").astype(int)

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)

print("\n==============================")
print("     MODEL EVALUATION")
print("==============================")

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Normal", "Anomaly"],
        zero_division=0
    )
)