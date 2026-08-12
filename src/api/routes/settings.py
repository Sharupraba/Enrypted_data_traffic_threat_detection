import os
import json
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("threat_detector.api.settings")
router = APIRouter()

CONFIG_PATH = os.path.join("data", "config.json")

class SettingsModel(BaseModel):
    abuseipdb_key: str = ""
    virustotal_key: str = ""
    xgboost_threshold: float = 50.0
    anomaly_threshold: float = 50.0
    idle_timeout: float = 8.0
    active_timeout: float = 120.0

def load_system_config() -> dict:
    defaults = {
        "abuseipdb_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "virustotal_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "xgboost_threshold": 50.0,
        "anomaly_threshold": 50.0,
        "idle_timeout": 8.0,
        "active_timeout": 120.0
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
                defaults.update(saved)
        except Exception as e:
            logger.error(f"Error reading configuration file: {e}")
    return defaults

def save_system_config(config_data: dict):
    os.makedirs("data", exist_ok=True)
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        
        # Dynamically set in environment for active modules
        os.environ["ABUSEIPDB_API_KEY"] = config_data.get("abuseipdb_key", "")
        os.environ["VIRUSTOTAL_API_KEY"] = config_data.get("virustotal_key", "")
    except Exception as e:
        logger.error(f"Error writing configuration file: {e}")
        raise e

@router.get("/settings")
def get_settings():
    """
    Get consolidated system settings and API configuration.
    """
    return load_system_config()

@router.post("/settings")
def update_settings(settings: SettingsModel):
    """
    Update system thresholds, timeouts, and API keys.
    """
    try:
        config_dict = settings.dict()
        save_system_config(config_dict)
        return {"status": "success", "message": "Settings updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")
