from fastapi import APIRouter, HTTPException
from .upload import _results

router = APIRouter()

@router.get("/results/{job_id}")
def get_results(job_id: str):
    if job_id not in _results:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found.")
    return {"job_id": job_id, "results": _results[job_id]["results"]}
