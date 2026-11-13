from typing import Any

from pydantic import BaseModel


class InvestigationResponse(BaseModel):
    alert_type: str
    severity: str

    mitre_id: str
    mitre_name: str
    tactic: str

    connection_count: int
    unique_destinations: int
    top_ports: list[int]
    top_destinations: list[str]

    summary: str
    recommendation: list[str]

    # Evidence provenance and observed connection states
    status_counts: dict[str, int]
    excluded_events: int
    retrieval_method: str
    evidence_events: list[dict[str, Any]]
