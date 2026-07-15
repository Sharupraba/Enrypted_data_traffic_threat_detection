import os
import json
import logging
from typing import Tuple, Optional

logger = logging.getLogger("zenith.enrichment.ja3")

_JA3_DATABASE = None
JA3_DB_PATH = os.path.join("data", "ja3_known_bad.json")

def load_ja3_database() -> dict:
    """
    Loads known malicious JA3 signatures from data/ja3_known_bad.json.
    Initializes a default threat list if the database file does not exist.
    """
    global _JA3_DATABASE
    if _JA3_DATABASE is None:
        if os.path.exists(JA3_DB_PATH):
            try:
                with open(JA3_DB_PATH, "r", encoding="utf-8") as f:
                    _JA3_DATABASE = json.load(f)
                logger.info(f"Loaded {len(_JA3_DATABASE)} threat signatures from local JA3 database.")
            except Exception as e:
                logger.error(f"Error loading JA3 database: {e}")
                _JA3_DATABASE = {}
        else:
            logger.info(f"JA3 signature database not found. Creating default at {JA3_DB_PATH}")
            _JA3_DATABASE = {
                "7c95e1e44383188fa6af70188ef3914a": "Cobalt Strike Beacon",
                "8947940c1ae8f31e67e9193153b9f915": "Emotet Downloader",
                "e2f6940c497475f49ce17c88ef39f915": "Sliver C2 Agent",
                "62ebf686c0c2d3cf3832d2f7f18ef391": "Trickbot Trojan Client"
            }
            # Save default
            os.makedirs("data", exist_ok=True)
            try:
                with open(JA3_DB_PATH, "w", encoding="utf-8") as f:
                    json.dump(_JA3_DATABASE, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to write default JA3 database: {e}")
    return _JA3_DATABASE

def lookup_ja3(ja3_hash: str) -> dict:
    """
    Looks up a JA3 hash against the local signature list.
    Returns details on matches and reputation weight.
    """
    if not ja3_hash:
        return {
            "ja3_match": False,
            "ja3_match_score": 0,
            "ja3_threat_label": None
        }
        
    db = load_ja3_database()
    hash_key = ja3_hash.strip().lower()
    
    if hash_key in db:
        label = db[hash_key]
        logger.info(f"JA3 Match found: {hash_key} -> {label}")
        return {
            "ja3_match": True,
            "ja3_match_score": 100,
            "ja3_threat_label": label
        }
        
    return {
        "ja3_match": False,
        "ja3_match_score": 0,
        "ja3_threat_label": None
    }
