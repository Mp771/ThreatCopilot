from fastapi import APIRouter, Query
from app.schemas.nlp_schema import NLPQuery
from app.services.nlp_service import parse_query
from app.services.elastic_service import search_events, get_top_attackers

router = APIRouter()


def generate_summary(results):
    if not results:
        return "No suspicious activity detected."

    count = len(results)
    ips = list(set([r.get("source_ip") for r in results if r.get("source_ip")]))

    return f"{count} events detected involving {len(ips)} unique IP address(es)."

@router.get("/welcome")
def welcome_message():
    return {
        "message": (
            "👋 Hi, I'm ThreatCopilot.\n"
            "I help you investigate security logs using natural language.\n"
            "You can try commands like:\n"
            "• Show failed vpn logins\n"
            "• Show brute force attempts more than 2\n"
            "• Show ssh failures yesterday\n"
            "• Show malware detected events"
        )
    }

@router.post("/nlp")
def nlp_search(payload: NLPQuery, session_id: str = Query("default")):

    parsed = parse_query(payload.query, session_id=session_id)

    # Handle greeting / chat queries
    if parsed.get("intent") == "chat":
        return {
            "summary": parsed["message"],
            "events": [],
            "timeline": []
        }

    # Handle threshold queries
    threshold = parsed.get("threshold")

    if threshold is not None:
        attackers = get_top_attackers(int(threshold))

        return {
            "parsed_intent": parsed,
            "attackers": attackers
        }

    # Normal investigation search
    results = search_events(
        event=parsed.get("event"),
        protocol=parsed.get("protocol"),
        user=parsed.get("user"),
        time_range=parsed.get("time_range")
    )

    summary = generate_summary(results)
    from app.services.history_service import save_investigation

    save_investigation(payload.query, summary, results)

    return {
        "parsed_intent": parsed,
        "summary": summary,
        "total_results": len(results),
        "events": results
    }