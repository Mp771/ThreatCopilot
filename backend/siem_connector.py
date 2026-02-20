from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

def get_failed_logins():
    response = es.search(
        index="soc-logs",
        query={
            "match": {
                "event.action": "failure"
            }
        }
    )
    return response["hits"]["hits"]