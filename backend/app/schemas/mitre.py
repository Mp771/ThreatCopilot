from pydantic import BaseModel

class MitreMapping(BaseModel):
    technique: str
    name: str
    tactic: str