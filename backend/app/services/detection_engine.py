from collections import defaultdict


def detect_suspicious_connections(connections):

    alerts = []

    ip_counter = defaultdict(int)

    for conn in connections:

        remote_ip = conn.get("remote_ip")

        if remote_ip in [
            None,
            "127.0.0.1",
            "::1"
        ]:
            continue

        ip_counter[remote_ip] += 1

    for ip, count in ip_counter.items():

        if count > 10:

            alerts.append({
                "severity": "MEDIUM",
                "alert_type": "High Connection Volume",
                "source_ip": ip,
                "description": f"{count} connections observed",
                "connection_count": count
            })

    return alerts