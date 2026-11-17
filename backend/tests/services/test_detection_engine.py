
from datetime import datetime, timezone

from app.services.detection_engine import detect_suspicious_connections


def make_connection(source, destination, timestamp):
    return {
        "local_ip": source,
        "remote_ip": destination,
        "@timestamp": timestamp,
    }


def test_alert_uses_its_own_event_window():
    connections = []

    for i in range(11):
        connections.append(
            make_connection(
                "10.0.0.1",
                "10.0.0.2",
                f"2026-11-17T10:00:{i:02d}Z",
            )
        )

    for i in range(11):
        connections.append(
            make_connection(
                "10.0.0.3",
                "10.0.0.4",
                f"2026-11-17T11:00:{i:02d}Z",
            )
        )

    alerts = detect_suspicious_connections(connections)

    assert len(alerts) == 2

    first = next(
        alert for alert in alerts
        if alert["source_ip"] == "10.0.0.1"
    )

    second = next(
        alert for alert in alerts
        if alert["source_ip"] == "10.0.0.3"
    )

    assert first["window_start"] == datetime(
        2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc
    )
    assert first["window_end"] == datetime(
        2026, 11, 17, 10, 0, 10, tzinfo=timezone.utc
    )

    assert second["window_start"] == datetime(
        2026, 11, 17, 11, 0, 0, tzinfo=timezone.utc
    )
    assert second["window_end"] == datetime(
        2026, 11, 17, 11, 0, 10, tzinfo=timezone.utc
    )


def test_alert_without_valid_timestamps_has_no_window():
    connections = [
        make_connection("10.0.0.1", "10.0.0.2", "invalid")
        for _ in range(11)
    ]

    alerts = detect_suspicious_connections(connections)

    assert len(alerts) == 1
    assert alerts[0]["window_start"] is None
    assert alerts[0]["window_end"] is None


def test_connection_threshold_remains_greater_than_ten():
    connections = [
        make_connection("10.0.0.1", "10.0.0.2", "2026-11-17T10:00:00Z")
        for _ in range(10)
    ]

    assert detect_suspicious_connections(connections) == []
