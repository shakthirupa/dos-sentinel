import psutil
import time

def syn_recv_count():
    connections=psutil.net_connections(kind="tcp")
    syn_count=0
    for connection in connections:
        if connection.status==psutil.CONN_SYN_RECV:
            syn_count+=1
    return syn_count
while True:
    syn_count=syn_recv_count()
    print(f"SYN_RECV connections: {syn_count}")
    time.sleep(1)