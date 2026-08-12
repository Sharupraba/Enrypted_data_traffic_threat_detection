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

@router.post("/flows/{flow_id}/allow")
async def allow_flow(flow_id: str):
    """
    Whitelist / allow a specific flow, marking it as Safe and Benign.
    """
    from src.api.database import update_flow_status
    success = await update_flow_status(flow_id, classification="Benign", severity="Safe", risk_score=0, attack_category="Benign")
    if not success:
        raise HTTPException(status_code=404, detail="Flow record not found.")
    return {"status": "success", "message": "Flow whitelisted/allowed successfully."}
