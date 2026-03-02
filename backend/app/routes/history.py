from fastapi import APIRouter
from app.services.history_service import (
    get_investigations,
    get_investigation_by_id
)

router = APIRouter()


@router.get("/history")
def investigation_history():

    investigations = get_investigations()

    return {
        "history": investigations
    }


@router.get("/history/{investigation_id}")
def investigation_detail(investigation_id: int):

    investigation = get_investigation_by_id(investigation_id)

    if not investigation:
        return {"error": "Investigation not found"}

    return investigation