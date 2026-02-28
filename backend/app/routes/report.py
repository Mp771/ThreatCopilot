from fastapi import APIRouter
from siem_connector import search_events
from app.services.report_generator import generate_report

router = APIRouter()

@router.post("/generate-report")
def create_report():

    events = search_events(event="failure")

    report = generate_report(events)

    return {"report": report}