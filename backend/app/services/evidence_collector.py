from elasticsearch import Elasticsearch
from collections import Counter

es = Elasticsearch("http://localhost:9200")


def collect_evidence(source_ip):

    response = es.search(
        index="live-network",
        size=500
    )

    connections = [
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]

    ports = []
    destinations = []

    for conn in connections:

        if conn.get("local_ip") != source_ip:
            continue

        remote_ip = conn.get("remote_ip")
        remote_port = conn.get("remote_port")

        # Ignore localhost and empty IPs
        if remote_ip in ["127.0.0.1", "::1", None]:
            continue

        # Ignore missing ports
        if remote_port is None:
            continue

        ports.append(remote_port)
        destinations.append(remote_ip)

    return {
        "connection_count": len(destinations),

        "unique_destinations": len(
            set(destinations)
        ),

        "top_ports": [
            port
            for port, _
            in Counter(ports).most_common(5)
        ],

        "top_destinations": [
            ip
            for ip, _
            in Counter(destinations).most_common(5)
        ]
    }