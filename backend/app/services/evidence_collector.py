from collections import Counter
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "live-network"
IGNORED_DESTINATIONS = {"127.0.0.1", "::1"}


def collect_evidence(source_ip: str) -> dict:
    """Collect network evidence for a source IP."""

    query = {
        "query": {
            "term": {
                "local_ip.keyword": source_ip
            }
        }
    }

    ports = Counter()
    destinations = Counter()
    statuses = Counter()
    events = []
    excluded_events = 0

    for hit in scan(
        client=es,
        index=INDEX_NAME,
        query=query,
        _source=[
            "@timestamp",
            "local_ip",
            "local_port",
            "remote_ip",
            "remote_port",
            "protocol",
            "status",
            "pid",
        ],
        preserve_order=False,
        size=500,
    ):
        event = hit.get("_source", {})
        remote_ip = event.get("remote_ip")
        remote_port = event.get("remote_port")
        status = event.get("status") or "UNKNOWN"

        if (
            not remote_ip
            or remote_ip in IGNORED_DESTINATIONS
            or remote_port is None
        ):
            excluded_events += 1
            continue

        ports[remote_port] += 1
        destinations[remote_ip] += 1
        statuses[status] += 1

        events.append({
            "event_id": hit.get("_id"),
            "index": hit.get("_index"),
            "timestamp": event.get("@timestamp"),
            "source_ip": event.get("local_ip"),
            "source_port": event.get("local_port"),
            "destination_ip": remote_ip,
            "destination_port": remote_port,
            "protocol": event.get("protocol"),
            "status": status,
            "pid": event.get("pid"),
        })

    return {
        "source_ip": source_ip,
        "connection_count": len(events),
        "unique_destinations": len(destinations),
        "top_ports": [
            port for port, _ in ports.most_common(5)
        ],
        "top_destinations": [
            ip for ip, _ in destinations.most_common(5)
        ],
        "status_counts": dict(statuses),
        "events": events,
        "excluded_events": excluded_events,
        "retrieval_method": "elasticsearch_scan",
    }