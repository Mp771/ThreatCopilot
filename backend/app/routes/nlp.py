from fastapi import APIRouter, Query
from app.schemas.nlp_schema import NLPQuery
from app.services.nlp_service import parse_query
from app.services.elastic_service import search_events, get_top_attackers

router = APIRouter()


def generate_summary(results):
    if not results:
        return "No suspicious activity detected."

    count = len(results)
    ips = list(set([r["source_ip"] for r in results]))

    return f"{count} events detected involving {len(ips)} unique IP address(es)."


@router.post("/nlp")
def nlp_search(payload: NLPQuery, session_id: str = Query("default")):
    parsed = parse_query(payload.query, session_id=session_id)

    if parsed["threshold"] is not None:
        attackers = get_top_attackers(parsed["threshold"])
        return {
            "parsed_intent": parsed,
            "attackers": attackers
        }

    results = search_events(
        event=parsed["event"],
        protocol=parsed["protocol"],
        user=parsed["user"],
        time_range=parsed["time_range"]
    )

    summary = generate_summary(results)

    return {
        "parsed_intent": parsed,
        "summary": summary,
        "total_results": len(results),
        "events": results
    }