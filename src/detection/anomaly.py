import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, List
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("zenith.detection.anomaly")

_ISOLATION_FOREST: IsolationForest = None

def _get_or_create_anomaly_model() -> IsolationForest:
    """
    Singleton loader for the IsolationForest zero-day anomaly detector.
    Constructs and fits a baseline model if not already initialized.
    """
    global _ISOLATION_FOREST
    if _ISOLATION_FOREST is None:
        # Initialize an IsolationForest model with 100 estimators
        iso = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
        
        # Train on a synthetic baseline matrix representing normal network traffic bounds
        synthetic_baseline = np.random.uniform(
            low=[0.1, 10.0, 0.0, 10.0, 0.0, 0.0, 0.0, 0.1, 0.0],
            high=[30.0, 1000.0, 1000.0, 100.0, 5.0, 5.0, 2.0, 50.0, 3.0],
            size=(200, 9)
        )
        iso.fit(synthetic_baseline)
        _ISOLATION_FOREST = iso
        logger.info("IsolationForest unsupervised zero-day model initialized.")
        
    return _ISOLATION_FOREST

def _extract_anomaly_vector(features: dict) -> np.ndarray:
    """
    Converts raw flow features into an anomaly feature array.
    """
    return np.array([[
        float(features.get("flow_duration", 0.0)),
        float(features.get("bytes_per_sec", 0.0)),
        float(features.get("packets_per_sec", 0.0)),
        float(features.get("total_packets", 0)),
        float(features.get("syn_count", 0)),
        float(features.get("rst_count", 0)),
        float(features.get("fin_count", 0)),
        float(features.get("pkt_len_mean", 0.0)),
        float(features.get("domain_entropy", 0.0))
    ]])

def compute_anomaly_score(features: dict) -> dict:
    """
    Calculates an unsupervised zero-day anomaly score (0.0% to 100.0%).
    
    Returns:
        {
            "anomaly_score": float,
            "is_zero_day_anomaly": bool
        }
    """
    try:
        model = _get_or_create_anomaly_model()
        vec = _extract_anomaly_vector(features)
        
        # Decision function: lower values represent greater anomaly degree
        raw_score = float(model.decision_function(vec)[0])
        
        # Normalize decision function output (range roughly -0.3 to +0.2) to 0.0 - 100.0%
        anomaly_score = max(0.0, min(100.0, (0.25 - raw_score) * 160.0))
        is_zero_day = bool(anomaly_score > 65.0)
        
        return {
            "anomaly_score": round(anomaly_score, 1),
            "is_zero_day_anomaly": is_zero_day
        }
    except Exception as e:
        logger.warning(f"Failed to calculate anomaly score: {e}")
        return {
            "anomaly_score": 0.0,
            "is_zero_day_anomaly": False
        }

def compute_anomaly_score_batch(features_list: List[dict]) -> List[dict]:
    """
    Batch calculates zero-day anomaly scores across multiple flows.
    """
    if not features_list:
        return []
        
    try:
        model = _get_or_create_anomaly_model()
        vecs = np.vstack([_extract_anomaly_vector(f) for f in features_list])
        raw_scores = model.decision_function(vecs)
        
        results = []
        for raw_score in raw_scores:
            anomaly_score = max(0.0, min(100.0, (0.25 - float(raw_score)) * 160.0))
            results.append({
                "anomaly_score": round(anomaly_score, 1),
                "is_zero_day_anomaly": bool(anomaly_score > 65.0)
            })
        return results
    except Exception as e:
        logger.warning(f"Batch anomaly calculation failed: {e}")
        return [{"anomaly_score": 0.0, "is_zero_day_anomaly": False} for _ in features_list]
