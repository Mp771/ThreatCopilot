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
        size=500
    )

    connections = [
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]

    alerts = detect_suspicious_connections(
        connections
    )

    for alert in alerts:
        save_alert(alert)

    return {
        "alerts_found": len(alerts),
        "alerts": alerts
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
        connection_count
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
        connection_count=row[6]
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
        SELECT *
        FROM alerts
        WHERE id=%s
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
        "description": row[4]
    }

    result = explain_alert(alert)

    evidence = collect_evidence(
        alert["source_ip"]
    )

    return InvestigationResponse(
    alert_type=result["alert_type"],
    severity=result["severity"],

    mitre_id=result["mitre_id"],
    mitre_name=result["mitre_name"],
    tactic=result["tactic"],

    connection_count=evidence["connection_count"],
    unique_destinations=evidence["unique_destinations"],

    top_ports=evidence["top_ports"],
    top_destinations=evidence["top_destinations"],

    summary=result["summary"],

    recommendation=result["recommendation"]
)
    