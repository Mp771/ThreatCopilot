from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

es = Elasticsearch("http://localhost:9200")


def build_time_filter(time_range):
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

    if event:
        must_clauses.append({"match": {"event.action": event}})

    if protocol:
        must_clauses.append({"match": {"network.protocol": protocol}})

    if user:
        must_clauses.append({"match": {"user.name": user}})

    time_filter = build_time_filter(time_range)
    if time_filter:
        must_clauses.append(time_filter)

    query = {
        "bool": {
            "must": must_clauses
        }
    }

    response = es.search(index="soc-logs", query=query)
    return response["hits"]["hits"]


def get_top_attackers(threshold=0):
    response = es.search(
        index="soc-logs",
        size=0,
        query={
            "match": {
                "event.action": "failure"
            }
        },
        aggs={
            "top_attackers": {
                "terms": {
                    "field": "source.ip"
                }
            }
        }
    )

    buckets = response["aggregations"]["top_attackers"]["buckets"]

    # Apply threshold filtering
    filtered = [b for b in buckets if b["doc_count"] > threshold]

    return filtered