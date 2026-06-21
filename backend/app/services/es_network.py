from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "live-network"

def store_connection(connection):

    es.index(
        index=INDEX_NAME,
        document=connection
    )