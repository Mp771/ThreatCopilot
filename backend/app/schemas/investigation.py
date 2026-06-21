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