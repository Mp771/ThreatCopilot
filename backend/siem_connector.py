from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")


def search_events(event=None, protocol=None, user=None):
    must_clauses = []

    if event:
        must_clauses.append({"match": {"event.action": event}})

    if protocol:
        must_clauses.append({"match": {"network.protocol": protocol}})

    if user:
        must_clauses.append({"match": {"user.name": user}})

    query = {
        "query": {
            "bool": {
                "must": must_clauses
            }
        }
    }

    response = es.search(index="soc-logs", query=query["query"])
    return response["hits"]["hits"]


def get_top_attackers():
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

    return response["aggregations"]["top_attackers"]["buckets"]