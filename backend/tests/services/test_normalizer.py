
import pytest

from app.services.ingestion.normalizer import (
    normalize_event,
    normalize_soc_log,
    normalize_network_event,
)


def test_authentication_failure_normalization():
    document = {
        "_index": "soc-logs",
        "_id": "test-auth-1",
        "_source": {
            "@timestamp": "2026-02-17T08:05:00",
            "event.action": "failure",
            "event.category": "authentication",
            "source.ip": "185.220.101.1",
            "user.name": "admin",
            "network.protocol": "vpn",
            "host.name": "server-1",
        },
    }

    event = normalize_soc_log(document)

    assert event.event_type == "authentication_failure"
    assert event.event_category == "authentication"
    assert event.source_ip == "185.220.101.1"
    assert event.username == "admin"
    assert event.action == "failure"
    assert event.source_document_id == "test-auth-1"


def test_successful_authentication_normalization():
    document = {
        "@timestamp": "2026-02-17T09:00:00",
        "event.action": "success",
        "event.category": "authentication",
        "source.ip": "192.168.1.5",
        "user.name": "john",
    }

    event = normalize_soc_log(document)

    assert event.event_type == "authentication_success"
    assert event.action == "success"
    assert event.source_ip == "192.168.1.5"


def test_malware_detection_normalization():
    document = {
        "@timestamp": "2026-02-17T11:00:00",
        "event.action": "malware_detected",
        "event.category": "malware",
        "source.ip": "10.0.0.4",
    }

    event = normalize_soc_log(document)

    assert event.event_type == "malware_detected"
    assert event.event_category == "malware"


def test_network_connection_normalization():
    document = {
        "@timestamp": "2026-06-21T06:17:31.924870",
        "local_ip": "192.168.1.10",
        "local_port": 50000,
        "remote_ip": "8.8.8.8",
        "remote_port": 443,
        "status": "ESTABLISHED",
        "pid": 1234,
    }

    event = normalize_network_event(document)

    assert event.event_type == "network_connection"
    assert event.local_ip == "192.168.1.10"
    assert event.remote_ip == "8.8.8.8"
    assert event.remote_port == 443
    assert event.connection_status == "ESTABLISHED"
    assert event.process_id == 1234


def test_listener_socket_normalization():
    document = {
        "@timestamp": "2026-06-21T06:17:31",
        "local_ip": "0.0.0.0",
        "local_port": 49678,
        "remote_ip": None,
        "remote_port": None,
        "status": "LISTEN",
        "pid": 1312,
    }

    event = normalize_network_event(document)

    assert event.event_type == "network_listener"
    assert event.local_ip == "0.0.0.0"
    assert event.remote_ip is None
    assert event.connection_status == "LISTEN"


def test_missing_remote_endpoint_is_allowed():
    document = {
        "@timestamp": "2026-06-21T06:17:31",
        "local_ip": "127.0.0.1",
        "local_port": 8080,
        "status": "NONE",
        "pid": 100,
    }

    event = normalize_network_event(document)

    assert event.local_ip == "127.0.0.1"
    assert event.remote_ip is None


def test_missing_timestamp_raises_error():
    document = {
        "event.action": "failure",
        "event.category": "authentication",
    }

    with pytest.raises(ValueError, match="missing a timestamp"):
        normalize_soc_log(document)


def test_unsupported_source_raises_error():
    document = {
        "@timestamp": "2026-06-21T06:17:31",
    }

    with pytest.raises(ValueError, match="Unsupported event source"):
        normalize_event(document, "unknown-source")

def test_naive_timestamp_is_marked_unknown():
    document = {
        "@timestamp": "2026-02-17T08:00:00",
        "event.action": "failure",
        "event.category": "authentication",
    }

    event = normalize_soc_log(document)

    assert event.timestamp_timezone_status == "NAIVE_UNKNOWN"
    assert event.timestamp.tzinfo is None


def test_utc_timestamp_is_marked_utc():
    document = {
        "@timestamp": "2026-11-11T19:03:43+00:00",
        "status": "ESTABLISHED",
    }

    event = normalize_network_event(document)

    assert event.timestamp_timezone_status == "UTC"
    assert event.timestamp.utcoffset().total_seconds() == 0

def test_non_utc_offset_is_marked_offset_aware():
    document = {
        "@timestamp": "2026-11-12T08:00:00+05:30",
        "status": "ESTABLISHED",
    }

    event = normalize_network_event(document)

    assert event.timestamp_timezone_status == "OFFSET_AWARE"
    assert event.timestamp.utcoffset().total_seconds() == 19800


def test_z_suffix_is_marked_utc():
    document = {
        "@timestamp": "2026-11-11T19:03:43Z",
        "status": "ESTABLISHED",
    }

    event = normalize_network_event(document)

    assert event.timestamp_timezone_status == "UTC"
    assert event.timestamp.utcoffset().total_seconds() == 0
