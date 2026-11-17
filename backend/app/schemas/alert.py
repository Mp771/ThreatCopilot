
from datetime import datetime
from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    severity: str
    alert_type: str
    source_ip: str
    destination_ip: str | None = None
    description: str
    connection_count: int
    created_at: datetime
    window_start: datetime | None = None
    window_end: datetime | None = None
