# Phase 3: ML Detection Engine

> **Duration:** 3 weeks  
> **Status:** Not started  
> **Depends on:** Phase 2 (100+ feature vectors in Parquet + Redis)  
> **Feeds into:** Phase 4 (Threat Intelligence), Phase 5 (Alert Engine)

---

## 1. Objective

Build the core classification and anomaly detection engine. The system must simultaneously:
- Identify **known threats** from labeled training patterns (supervised learning).
- Detect **unknown/zero-day threats** as deviations from normal baselines (unsupervised anomaly detection).
- Analyze **sequential packet patterns** from within flows (deep learning on sequences).
- Fuse all signals into a **single calibrated risk score** that drives the alert engine.
- Explain **why** each detection fired, using SHAP values, for analyst review.

---

## 2. Detection Components

### 2.1 Supervised Classification

Train gradient-boosted tree models on the feature vectors produced by Phase 2. These models learn the statistical signature of each known threat category.

**Models:**
- **XGBoost** — Primary classifier. Handles class imbalance well via `scale_pos_weight`. Fast inference (< 1ms per flow on CPU).
- **LightGBM** — Secondary classifier, used in ensemble. Faster training, slightly lower accuracy on small datasets.
- **Random Forest** — Tertiary classifier. High variance, but uncorrelated with gradient boosting models — improves ensemble diversity.

**Label Classes:**
```
BENIGN
C2_BEACONING
DATA_EXFILTRATION
PORT_SCAN
DDOS
BOTNET
DNS_TUNNELING
LATERAL_MOVEMENT
MALWARE_STAGING
PROTOCOL_TUNNELING
```

**Class Imbalance Strategy:**
> CICIDS2017 can be >90% BENIGN. Do NOT blindly downsample. Use a combined approach:
> 1. `class_weight='balanced'` param in scikit-learn models.
> 2. `scale_pos_weight = neg_count / pos_count` in XGBoost per class.
> 3. Apply SMOTE (`imbalanced-learn`) to the minority classes (C2, DNS tunneling, lateral movement) — these are typically <0.1% of flows.
> 4. **Never** apply SMOTE to the held-out test set (CIC-IDS-2019).

### 2.2 Isolation Forest — Anomaly Detection

Isolation Forest assigns an anomaly score to each flow by measuring how easily it can be "isolated" from the rest of the dataset. Flows that are easy to isolate (require few random cuts to separate) are anomalous.

**Use case:** Zero-day threats, novel malware, insider threats — any traffic pattern not seen in training data.

**Configuration:**
```python
IsolationForest(
    n_estimators=200,
    contamination=0.01,   # Expected 1% anomalous flows in production
    max_samples='auto',
    random_state=42,
)
```

**Output:** Anomaly score ∈ [-1, 1]. Normalize to [0, 1] for ensemble fusion: `(score + 1) / 2`.

**Training data:** Train ONLY on benign flows (one-class training). Including malicious flows in training degrades anomaly detection effectiveness.

### 2.3 LSTM Autoencoder — Temporal Anomaly Detection

The LSTM Autoencoder learns to reconstruct normal traffic sequences. Malicious traffic sequences (e.g., C2 beacons, slow exfiltration) have high reconstruction error because they deviate from the learned normal pattern.

**Architecture:**
```
Input: sequence of (packet_size, IAT) pairs, length N=50
        ↓
Encoder: LSTM(128) → LSTM(64) → latent vector (32)
        ↓
Decoder: RepeatVector(50) → LSTM(64) → LSTM(128) → Dense(2)
        ↓
Output: reconstructed sequence of (packet_size, IAT) pairs
Loss:   MSE between input and reconstruction
```

**Anomaly scoring:** `reconstruction_error = MSE(input, output)`. Normalize using the 99th percentile of training-set reconstruction errors as the maximum. `anomaly_score = min(1.0, error / p99_threshold)`.

**Training data:** Train ONLY on benign traffic sequences. The model learns what "normal" looks like and flags deviations. Like Isolation Forest, including malicious sequences in training is counterproductive.

**Input preparation:** Extract sequences of `(normalized_packet_size, normalized_IAT)` tuples from each flow, zero-padded to length 50 for short flows.

### 2.4 1D-CNN — Packet Sequence Classification

A 1D Convolutional Neural Network operates on the raw sequence of packet sizes per flow. Unlike statistical features (mean, std), CNNs can detect **structural patterns** in how packet sizes are arranged — e.g., a repeating pattern of `[64, 64, 1460, 64, 64, 1460]` that indicates a fixed protocol exchange.

**Architecture:**
```
Input: sequence of packet sizes, length N=50
        ↓
Conv1D(filters=64, kernel=3, activation='relu')
        ↓
MaxPooling1D(pool_size=2)
        ↓
Conv1D(filters=128, kernel=3, activation='relu')
        ↓
GlobalMaxPooling1D()
        ↓
Dense(64, activation='relu') → Dropout(0.3)
        ↓
Dense(num_classes, activation='softmax')
```

**Use cases:**
- **Protocol Tunneling:** Regular data packets embedded in random-size wrappers have distinctive size distributions.
- **Tor:** Tor circuits have characteristic cell sizes (512 bytes).
- **Custom C2 protocols:** Fixed command-response size patterns.

**Training data:** All labeled classes. This is a supervised model.

### 2.5 LSTM — Beaconing Sequence Classifier

A separate LSTM (distinct from the autoencoder) trained as a **supervised classifier** on IAT sequences. While the autoencoder detects "not normal", this LSTM learns "this specific pattern is beaconing".

**Architecture:**
```
Input: IAT sequence (ms), length N=50
        ↓
LSTM(128, return_sequences=True)
        ↓
LSTM(64, return_sequences=False)
        ↓
Dense(32, activation='relu')
        ↓
Dense(num_classes, activation='softmax')
```

**Label focus:** This model is most effective on C2_BEACONING vs BENIGN. Train with heavy oversampling of beaconing samples.

### 2.6 JA3 / JA3S Hash Matching

A Redis-backed O(1) lookup against known malicious TLS fingerprint databases. This is not ML — it is deterministic rule-based matching and is the fastest and most precise detection component.

**Databases:**
- Salesforce `ja3er.com` feed (updated daily).
- `threatintelligenceplatform.com` JA3 blacklist.
- Locally curated hash list from confirmed malware samples.

**Logic:**
```python
def ja3_match_score(ja3_hash: str, ja3s_hash: str) -> float:
    client_hit = redis.get(f"ja3:{ja3_hash}")    # Returns confidence: 0.0–1.0
    server_hit = redis.get(f"ja3s:{ja3s_hash}")  # Returns confidence: 0.0–1.0
    if client_hit and server_hit:
        return 1.0   # Both client and server match known-bad
    if client_hit:
        return 0.8   # Client is a known malware toolkit
    if server_hit:
        return 0.6   # Server responds like a known C2 framework
    return 0.0
```

---

## 3. Ensemble Threat Scoring

All detection signals are fused into a single score using a weighted linear combination. Weights are tunable per deployment profile.

```
FinalScore (0.0 – 100.0) =
    w1 × IsolationForestScore    (normalized 0–1)
  + w2 × AutoencoderScore        (normalized reconstruction error, 0–1)
  + w3 × XGBoostConfidence       (predicted probability of malicious class, 0–1)
  + w4 × CNNConfidence           (predicted probability, 0–1)
  + w5 × LSTMConfidence          (predicted probability, 0–1)
  + w6 × JA3MatchScore           (deterministic, 0–1)
  + w7 × DNSRiskScore            (from Phase 2 DNS features, 0–1)

Default weights (sum to 100):
  w1 = 15  (Isolation Forest — good for zero-day, noisy for beaconing)
  w2 = 15  (Autoencoder — temporal zero-day)
  w3 = 25  (XGBoost — primary known-threat classifier)
  w4 = 15  (CNN — structural pattern)
  w5 = 15  (LSTM — beaconing specialist)
  w6 = 10  (JA3 match — deterministic but not always available)
  w7 = 5   (DNS risk — compensating signal)

Alert thresholds:
  ≥ 80 → CRITICAL
  ≥ 60 → HIGH
  ≥ 40 → MEDIUM
  ≥ 20 → LOW
  < 20 → INFO (logged only)
```

**Score calibration:** Use Platt scaling or isotonic regression to calibrate raw model probabilities to true probabilities before weighting. Uncalibrated XGBoost probabilities are not reliable as weights.

---

## 4. SHAP Explainability

Every alert includes a SHAP (SHapley Additive exPlanations) block that translates the ML decision into analyst-readable reasoning.

**Implementation:**

```python
import shap

# TreeExplainer for XGBoost/Random Forest (fast, exact)
explainer = shap.TreeExplainer(xgboost_model)
shap_values = explainer(feature_vector)

# Top-5 contributing features
top_features = sorted(
    zip(feature_names, shap_values.values[0]),
    key=lambda x: abs(x[1]),
    reverse=True
)[:5]
```

**Alert SHAP output format:**
```json
{
  "alert_id": "...",
  "shap_explanation": [
    {"feature": "iat_autocorrelation", "value": 0.94, "contribution": "+42.3"},
    {"feature": "ja3_match_score",     "value": 1.0,  "contribution": "+18.1"},
    {"feature": "sni_label_entropy",   "value": 4.1,  "contribution": "+12.7"},
    {"feature": "fwd_pkt_len_cv",     "value": 0.02, "contribution": "+8.4"},
    {"feature": "flow_duration",      "value": 118.2, "contribution": "+3.1"}
  ],
  "human_readable": "Alert because traffic is highly periodic (beacon every ~60s), uses a known malicious TLS fingerprint, and connects to a high-entropy (likely DGA) domain."
}
```

**SHAP for deep models:** Use `shap.DeepExplainer` for LSTM and CNN models. Note: SHAP computation for deep models is 10–100x slower than tree models. For production, pre-compute SHAP for tree models (fast) and compute deep model SHAP only when `FinalScore > 60`.

---

## 5. Model Training Workflow

```
notebooks/01_data_exploration.ipynb    ← Data validation, dedup, class audit
notebooks/02_feature_engineering.ipynb ← Feature distributions, correlation
notebooks/03_model_training_classical.ipynb  ← XGBoost, RF, Isolation Forest
notebooks/04_model_training_deep.ipynb       ← LSTM, CNN, Autoencoder
notebooks/05_ensemble_evaluation.ipynb       ← Score fusion, threshold tuning, ROC/PRC
notebooks/06_shap_explainability.ipynb       ← SHAP analysis, feature importance
```

**Progressive evaluation:**
1. Evaluate each model individually on CICIDS validation set.
2. Evaluate ensemble on CICIDS validation set.
3. **Final evaluation on CIC-IDS-2019 held-out set ONLY** — never touch this during training.
4. If CIC-IDS-2019 performance is significantly worse than validation, there is dataset overfitting. Investigate.

---

## 6. Model Versioning

Every trained model artifact is saved with metadata:

```json
{
  "model_id": "xgboost_v1.0.0",
  "trained_on": ["CICIDS2017", "CTU-13"],
  "training_date": "2026-07-01",
  "validation_f1": 0.94,
  "held_out_f1": 0.87,
  "feature_list": ["flow_duration", "iat_autocorrelation", "..."],
  "scaler_path": "models/scaler_v1.pkl",
  "thresholds": {"CRITICAL": 80, "HIGH": 60, "MEDIUM": 40, "LOW": 20}
}
```

Model files are stored in `models/` and versioned with semantic versioning. See Phase 8 (Retraining Pipeline) for the A/B promotion process.

---

## 7. Deliverables

| File | Description |
|---|---|
| `src/models/classical/random_forest.py` | RF wrapper with fit/predict/explain |
| `src/models/classical/xgboost_model.py` | XGBoost wrapper |
| `src/models/classical/isolation_forest.py` | Isolation Forest (one-class, benign-only training) |
| `src/models/deep/lstm_model.py` | Supervised LSTM beaconing classifier |
| `src/models/deep/cnn_model.py` | 1D-CNN packet sequence classifier |
| `src/models/deep/autoencoder.py` | LSTM Autoencoder (benign-only training) |
| `src/models/tls_fingerprint.py` | JA3/JA3S Redis lookup engine |
| `src/models/ensemble.py` | Weighted score fusion + threshold logic |
| `src/models/trainer.py` | Full training orchestration CLI |
| `src/explainability/shap_explainer.py` | SHAP computation for all model types |
| `notebooks/03_model_training_classical.ipynb` | |
| `notebooks/04_model_training_deep.ipynb` | |
| `notebooks/05_ensemble_evaluation.ipynb` | |
| `notebooks/06_shap_explainability.ipynb` | |

---

## 8. Acceptance Criteria

| Metric | Target |
|---|---|
| XGBoost F1 (validation set) | ≥ 0.92 |
| XGBoost F1 (CIC-IDS-2019 held-out) | ≥ 0.82 |
| Ensemble ROC-AUC (held-out) | ≥ 0.95 |
| FP rate on self-generated benign | ≤ 5% |
| Inference latency per flow (CPU, p99) | < 50ms |
| SHAP computation time (XGBoost, p99) | < 10ms |
| Model metadata JSON present for every `.pkl`/`.pt` | 100% |
- [ ] CIC-IDS-2019 is confirmed NOT used during training (grep test in CI).
- [ ] Anomaly models trained on benign-only data (confirmed by training script assertion).
- [ ] Score calibration applied to all classifier probabilities.
