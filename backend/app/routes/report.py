from fastapi import APIRouter
from pydantic import BaseModel
from app.services.report_generator import generate_report

router = APIRouter()

class ReportRequest(BaseModel):
    events: list

@router.post("/generate-report")
def create_report(data: ReportRequest):

    report = generate_report(data.events)

    return {"report": report}