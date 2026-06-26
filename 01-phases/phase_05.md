# Phase 5 — Machine Learning Detection

> **Position in Pipeline:** Receives ML feature vector from Phase 4 → Outputs threat prediction + confidence score to Phase 6
> **Purpose:** Primary threat detection. Classify each network flow as Threat or Normal.

---

## Overview

Phase 5 is the **core detection engine** of the system. It applies a trained **Random Forest classifier** to each incoming feature vector and produces:
- A **classification label**: `Threat` or `Normal`
- A **confidence score**: probability from 0.0 to 1.0 (displayed as %)
- **Feature importance**: which features contributed most to the prediction (for explainability)

This is the only component that produces threat detections. All downstream phases (6, 7) build upon this prediction — they do not generate new detections.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  PHASE 5 — MACHINE LEARNING DETECTION                           │
│                                                                 │
│  INPUT: ML Feature Vector (from Phase 4)                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Random Forest Classifier                    │  │
│  │                                                          │  │
│  │  n_estimators : 200 trees                                │  │
│  │  max_depth    : None (fully grown)                       │  │
│  │  class_weight : balanced                                 │  │
│  │  criterion    : gini                                     │  │
│  │                                                          │  │
│  │  Input:  [feature_vector]                                │  │
│  │  Output: class_label + predict_proba                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  SHAP Explainer (post-prediction)                        │  │
│  │                                                          │  │
│  │  Computes contribution of each feature                   │  │
│  │  Returns top-5 features driving the prediction           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  OUTPUT:                                                        │
│  ┌───────────────────────────────┐                             │
│  │  classification : "THREAT"    │                             │
│  │  confidence     : 93%         │                             │
│  │  top_features   : [...]       │                             │
│  └───────────────────────────────┘                             │
└────────────────────────────────────────────────────────────────┘
```

---

## Model: Random Forest Classifier

### Why Random Forest?

| Reason | Explanation |
|---|---|
| **High accuracy on tabular data** | Flow metadata is tabular — RF consistently achieves high F1 on traffic datasets |
| **Handles class imbalance** | `class_weight='balanced'` adjusts for more benign flows than malicious |
| **No feature scaling required** | Decision trees are scale-invariant (Phase 4 scaling is still good practice) |
| **Feature importance built-in** | Naturally provides feature contribution scores per prediction |
| **Fast inference** | Sub-millisecond prediction for a single feature vector |
| **No black box** | Interpretable — each tree path can be explained |
| **Robust to noise** | Ensemble of 200 trees reduces overfitting from individual noisy features |

### Model Hyperparameters

| Parameter | Value | Reason |
|---|---|---|
| `n_estimators` | 200 | Balance between accuracy and speed |
| `max_features` | `sqrt(n_features)` | Default RF setting — reduces correlation between trees |
| `max_depth` | None | Fully grown trees for maximum accuracy |
| `min_samples_split` | 5 | Avoid overfitting on tiny leaf nodes |
| `class_weight` | `balanced` | Accounts for class imbalance in training data |
| `random_state` | 42 | Reproducibility |
| `n_jobs` | -1 | Use all CPU cores for training |

---

## Training

### Training Datasets

| Dataset | Threat Classes | Benign Source |
|---|---|---|
| CICIDS 2017 | DDoS, PortScan, BotNet, Infiltration | Normal enterprise traffic |
| CIC-IDS 2018 | Brute Force, Web Attacks, DoS | Normal enterprise traffic |
| CIC-IDS 2019 | Encrypted malicious flows (TLS-specific) | Normal HTTPS traffic |
| UNSW-NB15 | Fuzzers, Backdoors, Exploits | Normal enterprise traffic |
| CTU-13 | Botnet C2, P2P encrypted malware | Normal ISP traffic |

### Training Procedure

```
1. Load raw dataset CSV / Parquet files
2. Apply Phase 4 feature pipeline (impute → derive → scale → select)
   (Fit the pipeline on training data only — do NOT use test data)
3. Split: 80% train, 20% test (stratified by class label)
4. Train Random Forest on training set
5. Evaluate on test set (F1, ROC-AUC, confusion matrix)
6. If targets met → serialize model to models/random_forest.pkl
7. Serialize fitted feature pipeline to models/feature_pipeline.pkl
```

### Training Targets

| Metric | Target | Notes |
|---|---|---|
| Weighted F1-Score | ≥ 0.90 | Overall multi-class performance |
| ROC-AUC | ≥ 0.95 | Binary: threat vs normal |
| False Positive Rate | ≤ 5% | On benign-only traffic |
| Inference latency | < 50 ms | Per single flow |

---

## Inference

### Inference Process

```python
# Load model and pipeline at startup
rf_model        = joblib.load('models/random_forest.pkl')
feature_pipeline = joblib.load('models/feature_pipeline.pkl')

def detect(raw_features: dict) -> dict:
    # Step 1: Apply feature pipeline (transform only, not fit)
    feature_vector = feature_pipeline.transform(pd.DataFrame([raw_features]))

    # Step 2: Predict class
    prediction = rf_model.predict(feature_vector)[0]          # "THREAT" or "NORMAL"

    # Step 3: Get confidence score
    confidence = rf_model.predict_proba(feature_vector)[0][1] # Probability of THREAT class

    # Step 4: Get SHAP explanation
    top_features = explain(feature_vector)

    return {
        "classification": prediction,
        "confidence":     round(confidence * 100, 1),
        "top_features":   top_features
    }
```

### Example Output

```
{
  "classification": "THREAT",
  "confidence":     93.2,
  "top_features": [
    {"feature": "iat_cv",         "value": 0.02, "importance": 0.31},
    {"feature": "upload_ratio",   "value": 0.88, "importance": 0.24},
    {"feature": "syn_rate",       "value": 0.95, "importance": 0.19},
    {"feature": "ja3_match",      "value": 1.00, "importance": 0.14},
    {"feature": "flow_symmetry",  "value": 0.11, "importance": 0.09}
  ]
}
```

---

## Explainability — SHAP

> Source: `src/detection/explainer.py`

After each prediction, SHAP (SHapley Additive exPlanations) is used to identify which features most influenced the model's decision.

**How it works:**
- SHAP computes the marginal contribution of each feature to the final prediction
- Positive SHAP value = feature pushed prediction toward THREAT
- Negative SHAP value = feature pushed prediction toward NORMAL

**Use in the system:**
- Top 5 features surfaced in the threat alert shown in the dashboard
- Enables analysts to understand why a flow was flagged
- Displayed in the Flow Details panel

```python
import shap

explainer = shap.TreeExplainer(rf_model)

def explain(feature_vector: np.ndarray) -> list[dict]:
    shap_values = explainer.shap_values(feature_vector)
    # shap_values[1] = contribution toward THREAT class
    top_indices = np.argsort(np.abs(shap_values[1][0]))[::-1][:5]
    return [
        {
            "feature":    feature_names[i],
            "value":      float(feature_vector[0][i]),
            "importance": float(abs(shap_values[1][0][i]))
        }
        for i in top_indices
    ]
```

---

## Threat Classes Detected

| Threat Class | Primary Feature Signals |
|---|---|
| **C2 Beaconing** | Low IAT variance, fixed packet size, high IAT autocorrelation |
| **Port Scanning** | High SYN rate, low bytes/flow, many unique destination ports |
| **Data Exfiltration** | High upload ratio, large byte volume, off-hours timing |
| **DDoS / SYN Flood** | Very high SYN count, low FIN/ACK count, asymmetric packets |
| **TLS Malware** | Known-bad JA3 hash, weak cipher, self-signed certificate |
| **DGA Malware** | High domain entropy, high NXDOMAIN rate |
| **DNS Tunneling** | Very high DNS query frequency, oversized DNS responses |
| **Protocol Tunneling** | Port/protocol mismatch, suspicious ALPN, unusual packet sizes |

---

## Model Persistence

| File | Contents |
|---|---|
| `models/random_forest.pkl` | Trained Random Forest model |
| `models/feature_pipeline.pkl` | Fitted feature engineering pipeline |
| `models/selected_features.json` | List of selected feature names |
| `models/class_labels.json` | Class index → label mapping |
| `models/training_metrics.json` | F1, ROC-AUC, confusion matrix from training run |

---

## Trainer

> Source: `src/detection/trainer.py`

The trainer script is run offline (not during live detection) to produce and evaluate the model.

```
python -m src.detection.trainer \
  --dataset data/datasets/cicids2017 \
  --output  models/ \
  --eval-report reports/training_report.json
```

---

## ML Analytics (for Dashboard)

The following metrics are pre-computed during training and served to the ML Analytics dashboard panel:

| Metric | Format |
|---|---|
| Confusion Matrix | 2×2 matrix (TP, FP, FN, TN) |
| ROC Curve | (fpr[], tpr[]) arrays |
| Precision | Float |
| Recall | Float |
| F1 Score | Float |
| Feature Importance | [{feature, importance}] sorted list |

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | ML feature vector (60–80 normalized features, from Phase 4) |
| **OUTPUT** | `classification` (Threat/Normal), `confidence` (0–100%), `top_features` (SHAP) |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Primary ML model | `scikit-learn` RandomForestClassifier | Core detection engine |
| Model persistence | `joblib` | .pkl serialization |
| Explainability | `SHAP` | TreeExplainer for RF |
| Training evaluation | `scikit-learn` metrics | F1, ROC-AUC, confusion matrix |
| Data handling | `pandas`, `numpy` | Feature matrices |

---

## Deliverables

| File | Description |
|---|---|
| `src/detection/model.py` | Random Forest wrapper (load, predict, predict_proba) |
| `src/detection/trainer.py` | Offline training script |
| `src/detection/explainer.py` | SHAP feature importance computation |
| `src/detection/__init__.py` | Module init and exports |
| `models/random_forest.pkl` | Trained model (produced by trainer) |
| `models/feature_pipeline.pkl` | Fitted pipeline (produced by trainer) |
| `notebooks/03_model_training.ipynb` | Interactive training and evaluation notebook |
| `notebooks/04_model_evaluation.ipynb` | Metrics, confusion matrix, ROC curve, SHAP plots |
