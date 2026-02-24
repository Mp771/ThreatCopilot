from pydantic import BaseModel


class NLPQuery(BaseModel):
    query: str