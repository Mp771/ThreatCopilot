from fastapi import APIRouter, Query
from app.services.elastic_service import search_events, get_top_attackers

router = APIRouter()


@router.get("/search")
def dynamic_search(
    event: str = Query(None),
    protocol: str = Query(None),
    user: str = Query(None),
    time_range: str = Query(None)
):
    results = search_events(event, protocol, user, time_range)

    return {
        "total_results": len(results),
        "events": results
    }


@router.get("/top-attackers")
def top_attackers(threshold: int = Query(0)):
    attackers = get_top_attackers(threshold)

    return {
        "threshold": threshold,
        "attackers": attackers
    }