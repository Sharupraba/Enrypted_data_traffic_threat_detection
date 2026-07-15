from fastapi import APIRouter, HTTPException
from src.api.database import get_flows, get_flow, clear_database

router = APIRouter()

@router.get("/flows")
async def fetch_flows(limit: int = 1000):
    """
    Retrieve historical flows list from the database.
    """
    return await get_flows(limit=limit)

@router.get("/flows/{flow_id}")
async def fetch_flow_detail(flow_id: str):
    """
    Retrieve all details (full JSON log containing feature sub-groups) for a specific flow.
    """
    flow = await get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow record not found.")
    return flow

@router.delete("/flows/clear")
async def purge_flows():
    """
    Clear all records from the database.
    """
    await clear_database()
    return {"status": "cleared", "message": "Flow database purged successfully."}
