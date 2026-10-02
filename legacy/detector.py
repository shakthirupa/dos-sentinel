import psutil
import time
import pandas as pd
import joblib

# Load trained model
MODEL_FILE = "dos_model.pkl"
model = joblib.load(MODEL_FILE)

print("DoS Detector Started...")
print("Monitoring live network traffic...\n")


def get_traffic_features():

    connections = psutil.net_connections(kind="tcp")

    syn_recv = 0
    established = 0

    total_connections = len(connections)

    for connection in connections:

        if connection.status == psutil.CONN_SYN_RECV:
            syn_recv += 1

        elif connection.status == psutil.CONN_ESTABLISHED:
            established += 1

    return {
        "syn_recv": syn_recv,
        "established": established,
        "total_connections": total_connections
    }


while True:

    # Get current network traffic
    data = get_traffic_features()

    # Convert data into DataFrame
    input_data = pd.DataFrame([data])

    # Predict normal/anomaly
    prediction = model.predict(input_data)[0]

    # Calculate anomaly score
    score = model.decision_function(input_data)[0]

    print("----------------------------------------")

    if prediction == -1:

        print("🚨 ANOMALY DETECTED!")

    else:

        print("✅ Normal traffic")

    print(f"SYN_RECV:          {data['syn_recv']}")
    print(f"Established:       {data['established']}")
    print(f"Total connections: {data['total_connections']}")
    print(f"Anomaly Score:     {score:.4f}")

    time.sleep(1)