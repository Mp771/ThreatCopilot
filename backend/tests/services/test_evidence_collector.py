
from datetime import datetime, timezone

from app.services import evidence_collector


def test_missing_port_does_not_discard_valid_event(monkeypatch):
    fake_hits = [
        {
            "_id": "event-1",
            "_index": "live-network",
            "_source": {
                "@timestamp": "2026-11-17T10:00:00Z",
                "local_ip": "10.0.0.1",
                "local_port": 50000,
                "remote_ip": "10.0.0.2",
                "remote_port": 443,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "pid": 123,
            },
        },
        {
            "_id": "event-2",
            "_index": "live-network",
            "_source": {
                "@timestamp": "2026-11-17T10:00:01Z",
                "local_ip": "10.0.0.1",
                "local_port": 50001,
                "remote_ip": "10.0.0.2",
                "remote_port": None,
                "protocol": None,
                "status": "TIME_WAIT",
                "pid": 0,
            },
        },
    ]

    def fake_scan(**kwargs):
        return iter(fake_hits)

    monkeypatch.setattr(
        evidence_collector,
        "scan",
        fake_scan,
    )

    start = datetime(
        2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc
    )
    end = datetime(
        2026, 11, 17, 10, 0, 5, tzinfo=timezone.utc
    )

    result = evidence_collector.collect_evidence(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        window_start=start,
        window_end=end,
    )

    assert result["connection_count"] == 2
    assert result["unique_destinations"] == 1
    assert result["top_ports"] == [443]
    assert result["status_counts"] == {
        "ESTABLISHED": 1,
        "TIME_WAIT": 1,
    }
    assert result["excluded_events"] == 0
    assert len(result["events"]) == 2
    assert result["events"][1]["event_id"] == "event-2"
    assert result["events"][1]["destination_port"] is None


def test_missing_detection_window_does_not_query_elasticsearch(monkeypatch):
    def unexpected_scan(**kwargs):
        raise AssertionError(
            "Elasticsearch must not be queried without a detection window"
        )

    monkeypatch.setattr(
        evidence_collector,
        "scan",
        unexpected_scan,
    )

    result = evidence_collector.collect_evidence(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        window_start=None,
        window_end=None,
    )

    assert result["connection_count"] == 0
    assert result["events"] == []
    assert result["retrieval_method"] == "missing_detection_window"
