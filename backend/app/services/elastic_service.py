import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from app.core.config import ELASTIC_URL, INDEX_NAME
from typing import Optional

load_dotenv()
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

es = Elasticsearch(ELASTIC_URL)

MITRE_MAP = {
    "failure": "T1110 - Brute Force",
    "malware_detected": "T1204 - User Execution"
}


def build_time_filter(time_range: Optional[str]):
    if DEMO_MODE:
        return None

    if time_range == "last_24h":
        return {
            "range": {
                "@timestamp": {
                    "gte": "now-24h",
                    "lte": "now"
                }
            }
        }

    if time_range == "yesterday":
        return {
            "range": {
                "@timestamp": {
                    "gte": "now-1d/d",
                    "lt": "now/d"
                }
            }
        }

    return None


def search_events(event=None, protocol=None, user=None, time_range=None):
    must_clauses = []

    # Normalize case
    if event:
        event = event.lower()
        must_clauses.append({"term": {"event.action.keyword": event}})

    if protocol:
        protocol = protocol.lower()
        must_clauses.append({"term": {"network.protocol.keyword": protocol}})

    if user:
        user = user.lower()
        must_clauses.append({"term": {"user.name": user}})

    time_filter = build_time_filter(time_range)
    if time_filter:
        must_clauses.append(time_filter)

    if must_clauses:
        query = {
            "bool": {
                "must": must_clauses
            }
        }
    else:
        query = {
            "match_all": {}
        }

    response = es.search(index=INDEX_NAME, query=query)

    results = []
    for hit in response["hits"]["hits"]:
        source = hit["_source"]

        mitre = MITRE_MAP.get(source.get("event.action"))

        results.append({
            "timestamp": source.get("@timestamp"),
            "event": source.get("event.action"),
            "user": source.get("user.name"),
            "source_ip": source.get("source.ip"),
            "protocol": source.get("network.protocol"),
            "host": source.get("host.name"),
            "mitre_technique": mitre
        })

    return results


def get_top_attackers(threshold: int = 0):

    try:
        threshold = int(threshold)
    except:
        threshold = 0

    response = es.search(
        index=INDEX_NAME,
        size=0,
        query={
            "term": {
                "event.action.keyword": "failure"
            }
        },
        aggs={
            "top_attackers": {
                "terms": {
                    "field": "source.ip.keyword"
                }
            }
        }
    )

    buckets = response["aggregations"]["top_attackers"]["buckets"]

    return [b for b in buckets if b["doc_count"] > threshold]