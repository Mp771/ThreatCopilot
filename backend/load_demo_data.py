import json
from elasticsearch import Elasticsearch
from app.core.config import ELASTIC_URL, INDEX_NAME

es = Elasticsearch(ELASTIC_URL)

with open("demo_data/soc_demo_logs.json", "r") as f:
    logs = json.load(f)

# Delete index if exists
if es.indices.exists(index=INDEX_NAME):
    es.indices.delete(index=INDEX_NAME)

# Recreate index
es.indices.create(index=INDEX_NAME)

# Insert logs
for log in logs:
    es.index(index=INDEX_NAME, document=log)

print("Demo dataset loaded successfully.")