from pydantic import BaseModel
from typing import Any

class NLPResponse(BaseModel):
    intent: str
    success: bool
    response: Any