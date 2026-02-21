from fastapi import FastAPI, Query
from siem_connector import search_events, get_top_attackers

app = FastAPI()


@app.get("/")
def root():
    return {"message": "SIEM Copilot API Running"}


@app.get("/search")
def dynamic_search(
    event: str = Query(None),
    protocol: str = Query(None),
    user: str = Query(None)
):
    results = search_events(event, protocol, user)

    formatted = []
    for hit in results:
        source = hit["_source"]
        formatted.append({
            "timestamp": source.get("@timestamp"),
            "event": source.get("event.action"),
            "user": source.get("user.name"),
            "source_ip": source.get("source.ip"),
            "protocol": source.get("network.protocol"),
            "host": source.get("host.name")
        })

    return {
        "total_results": len(formatted),
        "events": formatted
    }


@app.get("/top-attackers")
def top_attackers():
    buckets = get_top_attackers()

    return {
        "attackers": buckets
    }