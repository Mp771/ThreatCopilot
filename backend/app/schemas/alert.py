from pydantic import BaseModel
from datetime import datetime


class AlertResponse(BaseModel):

    id: int

    severity: str

    alert_type: str

    source_ip: str

    description: str

    connection_count: int

    created_at: datetime