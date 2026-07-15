from fastapi import APIRouter
from src.api.database import get_alerts

router = APIRouter()

@router.get("/alerts")
async def fetch_alerts(limit: int = 1000):
    """
    Retrieve historical threat alerts from the database.
    """
    return await get_alerts(limit=limit)
