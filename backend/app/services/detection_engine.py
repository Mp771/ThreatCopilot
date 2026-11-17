
from collections import defaultdict
from datetime import datetime, timezone


IGNORED_IPS = {"127.0.0.1", "::1"}


def parse_event_timestamp(value):
    """Parse an event timestamp and normalize it to UTC."""

    if not value:
        return None

    try:
        if isinstance(value, datetime):
            timestamp = value
        else:
            timestamp = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def detect_suspicious_connections(connections):
    alerts = []
    connection_groups = defaultdict(list)

    for conn in connections:
        local_ip = conn.get("local_ip")
        remote_ip = conn.get("remote_ip")

        if not local_ip or not remote_ip:
            continue

        if local_ip in IGNORED_IPS or remote_ip in IGNORED_IPS:
            continue

        connection_groups[(local_ip, remote_ip)].append(conn)

    for (local_ip, remote_ip), events in connection_groups.items():
        count = len(events)

        if count <= 10:
            continue

        event_times = [
            timestamp
            for timestamp in (
                parse_event_timestamp(event.get("@timestamp"))
                for event in events
            )
            if timestamp is not None
        ]

        window_start = min(event_times) if event_times else None
        window_end = max(event_times) if event_times else None

        alerts.append({
            "severity": "MEDIUM",
            "alert_type": "High Connection Volume",
            "source_ip": local_ip,
            "destination_ip": remote_ip,
            "description": (
                f"{count} connections from {local_ip} "
                f"to {remote_ip}"
            ),
            "connection_count": count,
            "window_start": window_start,
            "window_end": window_end,
        })

    return alerts
