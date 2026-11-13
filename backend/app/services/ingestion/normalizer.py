
from typing import Any

from app.schemas.event import SecurityEvent


def _get_timestamp_timezone_status(timestamp: Any) -> str:
    from datetime import datetime

    parsed_timestamp = (
        timestamp
        if isinstance(timestamp, datetime)
        else datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    )

    if parsed_timestamp.tzinfo is None:
        return "NAIVE_UNKNOWN"

    if parsed_timestamp.utcoffset().total_seconds() == 0:
        return "UTC"

    return "OFFSET_AWARE"


def _get_source(document: dict[str, Any]) -> dict[str, Any]:
    """
    Accept either an Elasticsearch hit or a raw _source document.
    """
    source = document.get("_source")

    if isinstance(source, dict):
        return source

    return document


def _get_timestamp(source: dict[str, Any]) -> Any:
    """
    Retrieve the event timestamp without changing its timezone
    interpretation.
    """
    timestamp = source.get("@timestamp") or source.get("timestamp")

    if timestamp is None:
        raise ValueError("Event is missing a timestamp")

    return timestamp


def normalize_soc_log(
    document: dict[str, Any],
) -> SecurityEvent:
    """
    Normalize an ECS-style SIEM document.
    """
    source = _get_source(document)

    action = source.get("event.action")
    category = source.get("event.category")

    if category == "authentication" and action:
        event_type = f"authentication_{action}"
    elif action == "malware_detected":
        event_type = "malware_detected"
    elif category:
        event_type = str(category)
    elif action:
        event_type = str(action)
    else:
        event_type = "security_event"

    timestamp = _get_timestamp(source)
    timezone_status = _get_timestamp_timezone_status(timestamp)

    return SecurityEvent(
        event_type=event_type,
        event_category=category,
        timestamp=timestamp,
        timestamp_timezone_status=timezone_status,
        source_ip=source.get("source.ip"),
        username=source.get("user.name"),
        action=action,
        network_protocol=source.get("network.protocol"),
        hostname=source.get("host.name"),
        source_system="soc-logs",
        source_index=document.get("_index", "soc-logs"),
        source_document_id=document.get("_id"),
        raw_event=source,
    )


def normalize_network_event(
    document: dict[str, Any],
) -> SecurityEvent:
    """
    Normalize a local/remote network telemetry document.

    Local and remote endpoints are preserved separately.
    No source/destination direction is inferred.
    """
    source = _get_source(document)

    status = source.get("status")

    if status and str(status).upper() == "LISTEN":
        event_type = "network_listener"
    else:
        event_type = "network_connection"

    timestamp = _get_timestamp(source)
    timezone_status = _get_timestamp_timezone_status(timestamp)

    return SecurityEvent(
        event_type=event_type,
        event_category="network",
        timestamp=timestamp,
        timestamp_timezone_status=timezone_status,
        local_ip=source.get("local_ip"),
        local_port=source.get("local_port"),
        remote_ip=source.get("remote_ip"),
        remote_port=source.get("remote_port"),
        connection_status=status,
        process_id=source.get("pid"),
        source_system="live-network",
        source_index=document.get("_index", "live-network"),
        source_document_id=document.get("_id"),
        raw_event=source,
    )


def normalize_event(
    document: dict[str, Any],
    source_system: str,
) -> SecurityEvent:
    """
    Dispatch a document to the appropriate normalizer.
    """
    if source_system == "soc-logs":
        return normalize_soc_log(document)

    if source_system == "live-network":
        return normalize_network_event(document)

    raise ValueError(
        f"Unsupported event source: {source_system}"
    )
