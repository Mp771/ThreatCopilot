from pydantic import BaseModel

class NLPQuery(BaseModel):
    query: str
    session_id: str | None = None