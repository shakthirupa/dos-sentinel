import socket
import time

HOST = "127.0.0.1"
PORT = 8000

connections = []

print("Starting controlled localhost test...")
print("Target:", HOST, PORT)

try:

    # Open a limited number of connections
    for i in range(50):

        try:
            s = socket.create_connection(
                (HOST, PORT),
                timeout=2
            )

            connections.append(s)

            print(
                f"Connection {i + 1}/50 opened"
            )

        except Exception as e:
            print(
                f"Connection {i + 1} failed:",
                e
            )

    print("\nConnections currently open:",
          len(connections))

    print("Holding connections for 10 seconds...")

    time.sleep(10)

finally:

    print("\nClosing connections...")

    for s in connections:

        try:
            s.close()

        except:
            pass

    print("Test completed.")