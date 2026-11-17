
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
import app.routes.network as network
import app.services.evidence_collector as evidence_collector


client = TestClient(app)


def make_alert_row(
    window_start=None,
    window_end=None,
):
    """Return a database row in the same order as the investigation SELECT."""
    return (
        8,
        "MEDIUM",
        "High Connection Volume",
        "10.0.0.1",
        "12 connections from 10.0.0.1 to 10.0.0.2",
        datetime(2026, 11, 17, 14, 10, tzinfo=timezone.utc),
        12,
        "10.0.0.2",
        window_start,
        window_end,
    )


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.executed_query = None
        self.executed_params = None
        self.closed = False

    def execute(self, query, params=None):
        self.executed_query = query
        self.executed_params = params

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, row):
        self.fake_cursor = FakeCursor(row)
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def close(self):
        self.closed = True


def make_explanation(alert):
    return {
        "alert_type": alert["alert_type"],
        "severity": alert["severity"],
        "mitre_id": "Unknown",
        "mitre_name": "Unmapped",
        "tactic": "Unknown",
        "summary": "Available evidence is insufficient for a specific mapping.",
        "recommendation": [
            "Review the owning process if attribution is available.",
            "Check destination reputation.",
        ],
    }


def make_evidence():
    return {
        "connection_count": 12,
        "unique_destinations": 1,
        "top_ports": [53],
        "top_destinations": ["10.0.0.2"],
        "status_counts": {"TIME_WAIT": 12},
        "excluded_events": 0,
        "retrieval_method": "elasticsearch_scan_time_bounded",
        "events": [
            {
                "event_id": "event-001",
                "index": "live-network",
                "timestamp": "2026-11-17T14:09:55Z",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "source_port": 50001,
                "destination_port": 53,
                "protocol": None,
                "status": "TIME_WAIT",
                "pid": 0,
            },
            {
                "event_id": "event-002",
                "index": "live-network",
                "timestamp": "2026-11-17T14:09:56Z",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "source_port": 50002,
                "destination_port": 53,
                "protocol": None,
                "status": "TIME_WAIT",
                "pid": 0,
            },
        ],
    }


def install_database_mock(monkeypatch, row):
    fake_connection = FakeConnection(row)

    monkeypatch.setattr(
        network,
        "get_connection",
        lambda: fake_connection,
    )

    return fake_connection


def test_investigation_returns_valid_response(monkeypatch):
    start = datetime(2026, 11, 17, 14, 9, 52, tzinfo=timezone.utc)
    end = datetime(2026, 11, 17, 14, 10, 3, tzinfo=timezone.utc)

    fake_connection = install_database_mock(
        monkeypatch,
        make_alert_row(start, end),
    )

    monkeypatch.setattr(network, "explain_alert", make_explanation)
    monkeypatch.setattr(
        network,
        "collect_evidence",
        lambda **kwargs: make_evidence(),
    )

    response = client.get("/network/investigate/8")

    assert response.status_code == 200

    data = response.json()

    assert data["alert_type"] == "High Connection Volume"
    assert data["severity"] == "MEDIUM"
    assert data["connection_count"] == 12
    assert data["evidence_connection_count"] == 12
    assert data["unique_destinations"] == 1
    assert data["top_ports"] == [53]
    assert data["mitre_id"] == "Unknown"
    assert data["retrieval_method"] == "elasticsearch_scan_time_bounded"

    assert fake_connection.closed
    assert fake_connection.fake_cursor.closed


def test_investigation_returns_404_for_unknown_alert(monkeypatch):
    fake_connection = install_database_mock(monkeypatch, None)

    response = client.get("/network/investigate/99999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"

    assert fake_connection.closed
    assert fake_connection.fake_cursor.closed


def test_missing_timestamps_do_not_trigger_elasticsearch_scan(monkeypatch):
    install_database_mock(
        monkeypatch,
        make_alert_row(window_start=None, window_end=None),
    )

    monkeypatch.setattr(network, "explain_alert", make_explanation)

    def unexpected_scan(*args, **kwargs):
        raise AssertionError(
            "Elasticsearch scan must not run without a bounded time window"
        )

    # The real evidence collector is used here.
    # Its internal scan function is replaced with a failure guard.
    monkeypatch.setattr(evidence_collector, "scan", unexpected_scan)

    response = client.get("/network/investigate/8")

    assert response.status_code == 200

    data = response.json()

    assert data["evidence_connection_count"] == 0
    assert data["unique_destinations"] == 0
    assert data["evidence_events"] == []
    assert data["retrieval_method"] == "missing_detection_window"


def test_investigation_preserves_evidence_event_ids_and_timestamps(monkeypatch):
    start = datetime(2026, 11, 17, 14, 9, 52, tzinfo=timezone.utc)
    end = datetime(2026, 11, 17, 14, 10, 3, tzinfo=timezone.utc)

    install_database_mock(
        monkeypatch,
        make_alert_row(start, end),
    )

    monkeypatch.setattr(network, "explain_alert", make_explanation)
    monkeypatch.setattr(
        network,
        "collect_evidence",
        lambda **kwargs: make_evidence(),
    )

    response = client.get("/network/investigate/8")

    assert response.status_code == 200

    data = response.json()

    # Total retrieved count and returned event list are different concepts.
    assert data["evidence_connection_count"] == 12
    assert len(data["evidence_events"]) == 2

    first_event = data["evidence_events"][0]
    second_event = data["evidence_events"][1]

    assert first_event["event_id"] == "event-001"
    assert first_event["timestamp"] == "2026-11-17T14:09:55Z"

    assert second_event["event_id"] == "event-002"
    assert second_event["timestamp"] == "2026-11-17T14:09:56Z"
