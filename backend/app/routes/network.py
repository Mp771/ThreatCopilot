from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from app.services.network_monitor import capture_connections
from elasticsearch import Elasticsearch
from app.services.detection_engine import detect_suspicious_connections
from app.services.alert_service import save_alert
from app.services.alert_analyzer import explain_alert
from app.schemas.alert import AlertResponse
from app.schemas.investigation import InvestigationResponse
from fastapi import HTTPException
from app.services.evidence_collector import collect_evidence



router = APIRouter(
    prefix="/network",
    tags=["Network"]
)

es = Elasticsearch("http://localhost:9200")


@router.post("/capture")
def run_capture():

    capture_connections()

    return {
        "message": "Connections captured"
    }


@router.post("/analyze")
def analyze_network():

    response = es.search(
        index="live-network",
        size=500,
        query={
            "range": {
                "@timestamp": {
                    "gte": "now-5m",
                    "lte": "now"
                }
            }
        },
        sort=[
            {"@timestamp": {"order": "desc"}}
        ]
    )

    connections = [
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]

    alerts = detect_suspicious_connections(connections)

    event_times = []

    for connection in connections:
        raw_timestamp = connection.get("@timestamp")

        if not raw_timestamp:
            continue

        try:
            timestamp = datetime.fromisoformat(
                raw_timestamp.replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(
                    tzinfo=timezone.utc
                )

            event_times.append(timestamp)

        except (ValueError, TypeError):
            continue

    window_start = min(event_times) if event_times else None
    window_end = max(event_times) if event_times else None

    saved_alerts = []

    for alert in alerts:
        alert_id = save_alert(alert)

        saved_alerts.append({
            **alert,
            "id": alert_id
        })

    return {
        "events_analyzed": len(connections),
        "alerts_found": len(saved_alerts),
        "detection_window_start": window_start,
        "detection_window_end": window_end,
        "alerts": saved_alerts
    }


@router.get("/connections")
def get_connections():

    try:
        response = es.search(
            index="live-network",
            size=50,
            sort=[{"@timestamp": {"order": "desc"}}]
        )

        return [
            hit["_source"]
            for hit in response["hits"]["hits"]
        ]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    
from app.db.postgres import get_connection

@router.get(
    "/alerts",
    response_model=list[AlertResponse]
)
def get_alerts():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        id,
        severity,
        alert_type,
        source_ip,
        description,
        created_at,
        connection_count,
        destination_ip,
        window_start,
        window_end
    FROM alerts
    ORDER BY created_at DESC
    LIMIT 50
""")

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [
    AlertResponse(
        id=row[0],
        severity=row[1],
        alert_type=row[2],
        source_ip=row[3],
        description=row[4],
        created_at=row[5],
        connection_count=row[6],
	    destination_ip=row[7],
        window_start=row[8],
        window_end=row[9]
    )
    for row in rows
]

@router.get(
    "/investigate/{alert_id}",
    response_model=InvestigationResponse
)
def investigate_alert(alert_id: int):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
    """
    SELECT
        id,
        severity,
        alert_type,
        source_ip,
        description,
        created_at,
        connection_count,
        destination_ip,
        window_start,
        window_end
    FROM alerts
    WHERE id = %s
    """,
    (alert_id,)
  )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    alert = {
        "id": row[0],
        "severity": row[1],
        "alert_type": row[2],
        "source_ip": row[3],
        "description": row[4],
        "created_at": row[5],
        "connection_count": row[6],
        "destination_ip": row[7],
        "window_start": row[8],
        "window_end": row[9],
    }

    result = explain_alert(alert)
    result["summary"] = (
    f"Source IP {alert['source_ip']} generated "
    f"{alert['connection_count']} network connections. "
    f"{result['summary']}"
    )

    evidence = collect_evidence(
        source_ip=alert["source_ip"],
        destination_ip=alert["destination_ip"],
        window_start=alert["window_start"],
        window_end=alert["window_end"],
)

    return InvestigationResponse(
        alert_type=result["alert_type"],
        severity=result["severity"],
        mitre_id=result["mitre_id"],
        mitre_name=result["mitre_name"],
        tactic=result["tactic"],

        # Keep the original alert count distinct from retrieved evidence.
        connection_count=alert["connection_count"],
        evidence_connection_count=evidence["connection_count"],
        unique_destinations=evidence["unique_destinations"],
        top_ports=evidence["top_ports"],
        top_destinations=evidence["top_destinations"],

        summary=result["summary"],
        recommendation=result["recommendation"],

        status_counts=evidence["status_counts"],
        excluded_events=evidence["excluded_events"],
        retrieval_method=evidence["retrieval_method"],

        # Return up to 10 records, retaining their source IDs and timestamps.
        evidence_events=evidence["events"][:10],
    )
