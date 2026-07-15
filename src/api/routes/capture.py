import asyncio
import time
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from src.ingestion.live_capture import LiveSniffer
from src.parsing.flow_builder import FlowBuilder
from src.extraction.extractor import extract_features
from src.detection.model import detect_threat
from src.enrichment.enricher import enrich_threat
from src.scoring.risk_scorer import compute_risk_score
from src.api.database import insert_flow
from src.api.websocket import manager

logger = logging.getLogger("zenith.api.capture")
router = APIRouter()

# 1. Global state management
sniffer = LiveSniffer()
flusher_task = None

# Pipeline processor triggered when a flow record is completed
async def process_completed_flow(flow_dict: dict):
    try:
        # Step 1: Feature Extraction (Phase 3)
        features = extract_features(flow_dict)
        
        # Step 2: ML Inference (Phase 5)
        pred = {**features, **detect_threat(features)}
        
        # Step 3: Reputational Enrichment (Phase 6)
        enriched = await enrich_threat(pred)
        
        # Step 4: Weighted Risk Scoring (Phase 7)
        scored = {**enriched, **compute_risk_score(enriched)}
        
        # Append volume information for dashboard analytics
        scored["flow_duration"] = features.get("flow_duration", 0.0)
        scored["bytes_sent"] = features.get("bytes_sent", 0)
        scored["bytes_received"] = features.get("bytes_received", 0)
        scored["total_packets"] = features.get("total_packets", 0)
        
        # Step 5: SQLite Storage (Phase 8)
        await insert_flow(scored)
        
        # Step 6: Broadcast to active WebSocket connections (Phase 8)
        await manager.broadcast({
            "event": "new_flow",
            "data": scored
        })
        
        if scored.get("classification") == "Threat":
            await manager.broadcast({
                "event": "new_alert",
                "data": scored
            })
            
    except Exception as e:
        logger.error(f"Error processing completed flow: {e}")

# Global event loop reference to bridge Scapy's thread with FastAPI's main thread
main_loop = None

def flow_complete_callback(flow_dict: dict):
    """
    Bridge callback to schedule async flow processing inside the running loop.
    """
    global main_loop
    if main_loop is None:
        try:
            main_loop = asyncio.get_event_loop()
        except RuntimeError:
            logger.error("No active event loop found to delegate flow processing.")
            return

    try:
        asyncio.run_coroutine_threadsafe(process_completed_flow(flow_dict), main_loop)
    except Exception as e:
        logger.error(f"Error scheduling flow complete task on main loop: {e}")

# Global FlowBuilder instance configured with our pipeline callback
flow_builder = FlowBuilder(on_flow_complete=flow_complete_callback)

# sniffer callback to feed packet headers directly into FlowBuilder
def packet_sniff_callback(raw_pkt: dict):
    flow_builder.add_packet(raw_pkt)

async def _flusher_loop():
    """
    Periodic background loop that flushes expired flows from FlowBuilder.
    """
    logger.info("Background flow timeout flusher started.")
    while sniffer.is_running:
        try:
            now = time.time()
            # Offload synchronous dictionary manipulation to thread
            await asyncio.to_thread(flow_builder.flush_expired_flows, now)
        except Exception as e:
            logger.error(f"Error in background flow flusher: {e}")
        await asyncio.sleep(5)
    logger.info("Background flow timeout flusher stopped.")


# --- Endpoints ---

@router.get("/interfaces")
async def get_interfaces():
    """
    Retrieve list of physical and virtual interfaces.
    """
    return sniffer.list_interfaces()

@router.get("/capture/status")
async def get_capture_status():
    """
    Retrieve current sniffer state.
    """
    return {
        "is_running": sniffer.is_running,
        "interface": sniffer.interface
    }

@router.post("/capture/start")
async def start_capture(interface: str, background_tasks: BackgroundTasks):
    """
    Initiates live capture sniffing on a selected interface.
    """
    global main_loop
    try:
        main_loop = asyncio.get_running_loop()
    except RuntimeError:
        main_loop = asyncio.get_event_loop()

    if sniffer.is_running:
        raise HTTPException(status_code=400, detail="Sniffer is already running.")
        
    try:
        # Start capture sniffer
        sniffer.start(interface, packet_sniff_callback)
        
        # Start the background flusher task
        background_tasks.add_task(_flusher_loop)
        
        return {"status": "started", "interface": interface}
    except Exception as e:
        logger.error(f"Failed to start capture on {interface}: {e}")
        raise HTTPException(status_code=500, detail=f"Sniffer error: {e}")

@router.post("/capture/stop")
async def stop_capture():
    """
    Stops live capture sniffing.
    """
    if not sniffer.is_running:
        return {"status": "idle", "message": "Sniffer is not running."}
        
    sniffer.stop()
    return {"status": "stopped"}
