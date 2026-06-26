import uuid
import tempfile
import os
import shutil
import asyncio
import time
import logging
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
import joblib

from src.features.feature_map import TRAINING_FEATURES, clean_features

logger = logging.getLogger("zenith.upload")
router = APIRouter()

# --- Configurations ---
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
RESULT_TTL = 3600  # 1 hour
MODELS_DIR = Path("models")

# --- Resource Management ---
_results: dict[str, dict] = {}
_MODEL = None
_SCALER = None
_NFSTREAM_AVAILABLE = None


def _check_nfstream() -> bool:
    global _NFSTREAM_AVAILABLE
    if _NFSTREAM_AVAILABLE is None:
        try:
            from nfstream import NFStreamer  # noqa: F401
            _NFSTREAM_AVAILABLE = True
        except (ImportError, OSError):
            _NFSTREAM_AVAILABLE = False
    return _NFSTREAM_AVAILABLE


def get_model_and_scaler():
    """Singleton pattern for loading models."""
    global _MODEL, _SCALER
    if _MODEL is None or _SCALER is None:
        model_path = MODELS_DIR / "xgboost_model.pkl"
        scaler_path = MODELS_DIR / "scaler.pkl"

        if not model_path.exists() or not scaler_path.exists():
            logger.error("Predictive models missing in models/ directory")
            raise HTTPException(
                status_code=503,
                detail="Detection engine offline: Models not initialized."
            )

        _MODEL = joblib.load(model_path)
        _SCALER = joblib.load(scaler_path)
        logger.info("Detection models loaded into memory.")

    return _MODEL, _SCALER


def cleanup_old_results():
    now = time.time()
    expired = [jid for jid, data in _results.items() if now - data["timestamp"] > RESULT_TTL]
    for jid in expired:
        del _results[jid]
    if expired:
        logger.debug(f"Cleaned up {len(expired)} expired analysis results.")


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # 1. Validation: Size & Extension
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Unsupported file format. Use .pcap or .pcapng")

    # Note: file.size might be None depending on the client; we'll check during streaming
    
    # 2. Engine Availability
    if not _check_nfstream():
        logger.error("PCAP processing failed: Npcap driver not found on host.")
        raise HTTPException(
            status_code=503,
            detail="NFStream Engine Offline: Npcap driver required. Install from https://npcap.com"
        )

    model, scaler = get_model_and_scaler()
    cleanup_old_results()

    # 3. Secure Streaming to Disk
    fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
    bytes_read = 0
    
    try:
        with os.fdopen(fd, "wb") as buf:
            while chunk := await file.read(65536):  # 64KB chunks
                bytes_read += len(chunk)
                if bytes_read > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="File too large (limit 100MB).")
                buf.write(chunk)

        # 4. Verify Magic Bytes
        with open(tmp_path, "rb") as f:
            header = f.read(4)
        if header not in [b"\xa1\xb2\xc3\xd4", b"\xd4\xb2\xc3\xa1", b"\x0a\x0d\x0d\x0a"]:
            raise HTTPException(status_code=400, detail="Verification failed: Invalid PCAP signature.")

        # 5. Non-blocking Feature Extraction
        logger.info(f"Starting feature extraction for {file.filename} ({bytes_read} bytes)")
        from src.features.extractor import extract_features
        df = await asyncio.to_thread(extract_features, tmp_path)

        if df is None or df.empty:
            logger.warning(f"No valid flows extracted from {file.filename}")
            raise HTTPException(status_code=422, detail="Incompatible PCAP: No flows extracted.")

        # 6. Non-blocking Inference
        logger.info(f"Running XGBoost inference on {len(df)} flows...")
        
        def run_inference():
            feature_df = clean_features(df)
            X_scaled = scaler.transform(feature_df[TRAINING_FEATURES])
            preds = model.predict(X_scaled)
            probs = model.predict_proba(X_scaled)[:, 1]
            return preds, probs

        predictions, probabilities = await asyncio.to_thread(run_inference)

        # 7. Map Results
        results_list = []
        for i, row in df.iterrows():
            results_list.append({
                "flow_id":    int(i),
                "src_ip":     row.get("src_ip", ""),
                "dst_ip":     row.get("dst_ip", ""),
                "src_port":   int(row.get("src_port", 0)),
                "dst_port":   int(row.get("dst_port", 0)),
                "protocol":   int(row.get("protocol", 0)),
                "sni":        row.get("sni", ""),
                "prediction": "Threat" if predictions[i] == 1 else "Benign",
                "confidence": round(float(probabilities[i]) * 100, 1),
            })

        job_id = str(uuid.uuid4())
        _results[job_id] = {"timestamp": time.time(), "results": results_list}
        
        logger.info(f"Analysis complete for {job_id}. Threat count: {sum(1 for r in results_list if r['prediction'] == 'Threat')}")

        return {
            "job_id":       job_id,
            "total_flows":  len(results_list),
            "threat_count": sum(1 for r in results_list if r["prediction"] == "Threat"),
            "benign_count": sum(1 for r in results_list if r["prediction"] == "Benign"),
            "results":      results_list,
        }

    except Exception as e:
        if not isinstance(e, HTTPException):
            logger.exception(f"Unexpected error during PCAP processing: {e}")
            raise HTTPException(status_code=500, detail="Internal processing error.")
        raise e
    finally:
        # Strict cleanup of temporary PCAP
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
