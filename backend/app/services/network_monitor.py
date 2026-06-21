import psutil
from datetime import datetime
from app.services.es_network import store_connection

def capture_connections():

    for conn in psutil.net_connections(kind="inet"):

        try:

            document = {
                "@timestamp": datetime.utcnow().isoformat(),
                "local_ip": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip if conn.raddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid
            }

            store_connection(document)

        except Exception as e:
            print(e)