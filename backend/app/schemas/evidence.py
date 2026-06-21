from pydantic import BaseModel

class EvidenceResponse(BaseModel):
    connection_count: int
    top_ports: list[int]
    top_destinations: list[str]