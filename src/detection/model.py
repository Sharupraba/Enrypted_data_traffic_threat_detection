import os
import logging
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, Any
from src.engineering.feature_pipeline import transform_to_model_input
from .explainer import explain_prediction

logger = logging.getLogger("zenith.detection.model")

_MODEL = None
_SCALER = None
_FEATURE_COLS = None

def load_model_assets(models_dir: str = "models") -> Tuple[Any, Any, list]:
    """
    Singleton loader for model, scaler, and feature column list.
    """
    global _MODEL, _SCALER, _FEATURE_COLS
    if _MODEL is None or _SCALER is None or _FEATURE_COLS is None:
        model_path = os.path.join(models_dir, "xgboost_model.pkl")
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        feature_cols_path = os.path.join(models_dir, "feature_cols.pkl")
        
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            raise FileNotFoundError("Model assets (xgboost_model.pkl or scaler.pkl) not found.")
            
        _MODEL = joblib.load(model_path)
        _SCALER = joblib.load(scaler_path)
        
        if os.path.exists(feature_cols_path):
            _FEATURE_COLS = joblib.load(feature_cols_path)
        else:
            # Reconstruct list of 30 standard features in exact training order
            _FEATURE_COLS = [
                'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                'Fwd Packet Length Max', 'Fwd Packet Length Min',
                'Bwd Packet Length Mean', 'Bwd Packet Length Std',
                'Bwd Packet Length Max', 'Bwd Packet Length Min',
                'Flow Bytes/s', 'Flow Packets/s',
                'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
                'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                'Fwd PSH Flags', 'SYN Flag Count', 'Down/Up Ratio'
            ]
            
    return _MODEL, _SCALER, _FEATURE_COLS

def detect_threat(raw_features: dict) -> dict:
    """
    Takes a raw dictionary of features (Phase 3 schema).
    Runs preprocessing, derived feature calculation, scaling, XGBoost classification.
    Returns: {
        "classification": "Threat" | "Benign",
        "confidence": float (0.0 - 100.0),
        "top_features": list of dicts (SHAP explanation details)
    }
    """
    model, scaler, feature_cols = load_model_assets()
    
    # 1. Transform raw extraction dictionary to a single row DataFrame
    raw_df = pd.DataFrame([raw_features])
    model_input_df = transform_to_model_input(raw_df)
    
    # 2. Re-order features to exact training order
    X = model_input_df[feature_cols]
    
    # 3. Apply standard scaler
    X_scaled = scaler.transform(X)
    
    # 4. Predict
    prediction = int(model.predict(X_scaled)[0])
    probabilities = model.predict_proba(X_scaled)[0]
    
    # Probability of class 1 (Threat)
    confidence = float(probabilities[1])
    
    # 5. Explanations (SHAP)
    top_features = explain_prediction(model, scaler, feature_cols, X_scaled, prediction)
    
    classification = "Threat" if prediction == 1 else "Benign"
    
    return {
        "classification": classification,
        "confidence": round(confidence * 100.0, 1),
        "top_features": top_features
    }
