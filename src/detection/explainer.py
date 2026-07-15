import logging
import numpy as np
from typing import List

logger = logging.getLogger("zenith.detection.explainer")

_EXPLAINER = None

def get_shap_explainer(model):
    """
    Initializes and returns a singleton SHAP TreeExplainer.
    Falls back gracefully if the SHAP module is not installed.
    """
    global _EXPLAINER
    if _EXPLAINER is None:
        try:
            import shap
            _EXPLAINER = shap.TreeExplainer(model)
        except Exception as e:
            logger.info(f"SHAP TreeExplainer not initialized: {e}. Using fallback feature importance.")
    return _EXPLAINER

def explain_prediction(model, scaler, feature_cols: List[str], scaled_features: np.ndarray, prediction: int) -> List[dict]:
    """
    Computes SHAP values to explain a specific Threat classification.
    If SHAP is unavailable, returns feature contribution using static model importances.
    """
    # Only explain threat predictions (label = 1)
    if prediction != 1:
        return []
        
    explainer = get_shap_explainer(model)
    if explainer is not None:
        try:
            shap_values = explainer.shap_values(scaled_features)
            
            # Format depends on SHAP and XGBoost version (1D array, 2D array, or list of arrays)
            if isinstance(shap_values, list):
                row_values = shap_values[1][0]
            elif len(shap_values.shape) == 2:
                row_values = shap_values[0]
            else:
                row_values = shap_values
                
            explanations = []
            for i, name in enumerate(feature_cols):
                val = float(scaled_features[0][i])
                shap_val = float(row_values[i])
                explanations.append({
                    "feature": name,
                    "value": val,
                    "importance": abs(shap_val),
                    "direction": "Threat" if shap_val > 0 else "Benign"
                })
                
            # Return top 5 most important features driving the threat classification
            return sorted(explanations, key=lambda x: x["importance"], reverse=True)[:5]
        except Exception as e:
            logger.error(f"Error computing SHAP values: {e}")
            
    # Fallback to model's default feature importances
    try:
        importances = model.feature_importances_
        explanations = []
        for i, name in enumerate(feature_cols):
            val = float(scaled_features[0][i])
            imp = float(importances[i])
            explanations.append({
                "feature": name,
                "value": val,
                "importance": imp,
                "direction": "Threat"
            })
        return sorted(explanations, key=lambda x: x["importance"], reverse=True)[:5]
    except Exception as e:
        logger.error(f"Error computing fallback importance: {e}")
        return []
