import uuid
import tempfile
import os
import asyncio
import logging
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from src.ingestion.pcap_reader import read_pcap
from src.parsing.flow_builder import FlowBuilder
from src.extraction.extractor import extract_features
from src.detection.model import detect_threat_batch
from src.enrichment.enricher import enrich_threat
from src.scoring.risk_scorer import compute_risk_score
from src.api.database import insert_flows_batch
from src.api.websocket import manager

logger = logging.getLogger("zenith.api.upload")
router = APIRouter()

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Upload and analyze offline PCAP or PCAPNG traffic files.
    Processes packets, builds flows, runs ML classification, 
    performs threat intel enrichment, and persists logs in SQLite.
    """
    # 1. Validation
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Unsupported file format. Use .pcap or .pcapng")

    # 2. Stream to a temporary file
    fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
    bytes_read = 0
    try:
        with os.fdopen(fd, "wb") as buf:
            while chunk := await file.read(65536):  # 64KB chunks
                bytes_read += len(chunk)
                if bytes_read > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="File too large (limit 100MB).")
                buf.write(chunk)

        # 3. Build flows in memory using a local builder
        pcap_flows = []
        def on_pcap_flow_complete(flow_dict: dict):
            pcap_flows.append(flow_dict)
            
        builder = FlowBuilder(on_flow_complete=on_pcap_flow_complete)
        
        # Offload Scapy sequential PCAP parsing to background thread
        def parse_pcap():
            for pkt in read_pcap(tmp_path):
                builder.add_packet(pkt)
            builder.flush_all_flows()
            
        logger.info(f"Parsing PCAP file: {file.filename} ({bytes_read} bytes)...")
        await asyncio.to_thread(parse_pcap)
        
        if not pcap_flows:
            return {
                "total_flows": 0,
                "threat_count": 0,
                "benign_count": 0,
                "results": []
            }
        
        # 4. High-speed Batch Feature Extraction & ML Detection
        logger.info(f"Extracted {len(pcap_flows)} flows. Running batch feature extraction & ML inference...")
        features_list = [extract_features(flow) for flow in pcap_flows]
        batch_preds = detect_threat_batch(features_list)
        
        results_list = []
        scored_flows = []
        threat_count = 0
        benign_count = 0
        
        for idx, features in enumerate(features_list):
            pred = {**features, **batch_preds[idx]}
            
            # Threat Intel Enrichment (Phase 6)
            enriched = await enrich_threat(pred)
            
            # Risk Scoring (Phase 7)
            scored = {**enriched, **compute_risk_score(enriched)}
            
            # Append traffic volume metrics
            scored["flow_duration"] = features.get("flow_duration", 0.0)
            scored["bytes_sent"] = features.get("bytes_sent", 0)
            scored["bytes_received"] = features.get("bytes_received", 0)
            scored["total_packets"] = features.get("total_packets", 0)
            
            scored_flows.append(scored)
            
            if scored.get("classification") == "Threat":
                await manager.broadcast({
                    "event": "new_alert",
                    "data": scored
                })
                threat_count += 1
            else:
                benign_count += 1
                
            results_list.append({
                "flow_id": scored.get("flow_id"),
                "src_ip": scored.get("src_ip"),
                "dst_ip": scored.get("dst_ip"),
                "src_port": scored.get("src_port"),
                "dst_port": scored.get("dst_port"),
                "protocol": scored.get("protocol"),
                "sni": scored.get("sni"),
                "prediction": scored.get("classification"),
                "confidence": scored.get("confidence"),
                "risk_score": scored.get("risk_score"),
                "severity": scored.get("severity")
            })
            
        # High-speed batch database save
        await insert_flows_batch(scored_flows)
            
        logger.info(f"PCAP Analysis complete. Threat count: {threat_count}")
        return {
            "total_flows": len(results_list),
            "threat_count": threat_count,
            "benign_count": benign_count,
            "results": results_list
        }

    except Exception as e:
        if not isinstance(e, HTTPException):
            logger.exception(f"Unexpected error parsing upload PCAP: {e}")
            raise HTTPException(status_code=500, detail="Internal processing error during PCAP analysis.")
        raise e
    finally:
        # Cleanup temporary file from disk
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
