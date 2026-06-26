# Phase 4 — Feature Engineering

> **Position in Pipeline:** Receives structured metadata dataset from Phase 3 → Outputs ML-ready feature vector to Phase 5
> **Purpose:** Transform raw metadata into a clean, normalized, ML-ready feature set.

---

## Overview

Phase 4 receives the structured metadata dataset from Phase 3 and prepares it for machine learning. Raw extracted features often contain missing values, different scales, and redundant information. This phase:

1. **Handles missing values** — fills gaps left by features not available in every flow
2. **Generates derived features** — computes ratio-based and combined signals
3. **Scales and normalizes** — standardizes all features to compatible ranges
4. **Selects important features** — removes noise and redundant columns

The output is a clean, fixed-dimension feature vector ready for the Random Forest classifier in Phase 5.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4 — FEATURE ENGINEERING                                   │
│                                                                  │
│  INPUT: Structured Metadata Dataset (from Phase 3)               │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Step 1: Missing Value Handling                         │    │
│  │  SimpleImputer — median for numerical, 0 for flags      │    │
│  └──────────────────────────────┬──────────────────────────┘    │
│                                 │                                │
│  ┌──────────────────────────────▼──────────────────────────┐    │
│  │  Step 2: Derived Feature Generation                     │    │
│  │  Upload Ratio | Download Ratio | Packet Rate            │    │
│  │  Flow Symmetry | Byte Ratio | Header Ratio              │    │
│  └──────────────────────────────┬──────────────────────────┘    │
│                                 │                                │
│  ┌──────────────────────────────▼──────────────────────────┐    │
│  │  Step 3: Feature Scaling                                │    │
│  │  StandardScaler (mean=0, std=1)                         │    │
│  └──────────────────────────────┬──────────────────────────┘    │
│                                 │                                │
│  ┌──────────────────────────────▼──────────────────────────┐    │
│  │  Step 4: Normalization                                  │    │
│  │  MinMaxScaler → [0, 1] bounds                           │    │
│  └──────────────────────────────┬──────────────────────────┘    │
│                                 │                                │
│  ┌──────────────────────────────▼──────────────────────────┐    │
│  │  Step 5: Feature Selection                              │    │
│  │  SelectKBest / Random Forest Feature Importance         │    │
│  │  Remove low-variance and low-importance features        │    │
│  └──────────────────────────────┬──────────────────────────┘    │
│                                 │                                │
│  OUTPUT: ML Feature Vector (60–80 features per flow)            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Missing Value Handling

> Source: `src/engineering/preprocessor.py`

Not all features are available in every flow. For example:
- TLS features are null for non-TLS flows (plain HTTP, DNS)
- DNS features are null for non-DNS flows
- `burst_count` is 0 for very short flows

| Feature Group | Missing Value Strategy |
|---|---|
| Numerical flow features | Fill with **column median** |
| TCP flag counts | Fill with **0** |
| TLS features | Fill with **-1** (indicates "not a TLS flow") |
| DNS features | Fill with **0** or empty string |
| Boolean flags | Fill with **False / 0** |

**Implementation:**
```python
from sklearn.impute import SimpleImputer

imputer_numerical = SimpleImputer(strategy='median')
imputer_flags     = SimpleImputer(strategy='constant', fill_value=0)
imputer_tls       = SimpleImputer(strategy='constant', fill_value=-1)
```

---

## Step 2 — Derived Feature Generation

> Source: `src/engineering/derived_features.py`

Derived features combine raw extracted values to produce higher-signal ratios and patterns. These are computed **before** scaling.

| Derived Feature | Formula | Interpretation |
|---|---|---|
| `upload_ratio` | `bytes_sent / (bytes_sent + bytes_received)` | Upload-heavy traffic (exfiltration signal) |
| `download_ratio` | `bytes_received / (bytes_sent + bytes_received)` | Download-heavy traffic |
| `packet_rate` | `total_packets / flow_duration` | Overall packet throughput |
| `fwd_packet_rate` | `total_fwd_packets / flow_duration` | Forward packet frequency |
| `bwd_packet_rate` | `total_bwd_packets / flow_duration` | Backward packet frequency |
| `flow_symmetry` | `1 - abs(fwd_pkts - bwd_pkts) / total_pkts` | 1.0 = symmetric, 0.0 = one-directional |
| `byte_ratio` | `bytes_sent / (bytes_received + 1)` | Upload vs download ratio |
| `header_ratio` | `header_bytes / total_bytes` | Header overhead vs payload size |
| `pkt_size_cv` | `std(pkt_sizes) / mean(pkt_sizes)` | Coefficient of variation (C2 = very low) |
| `iat_cv` | `iat_std / (iat_mean + 1)` | IAT variability (beacon = very low) |

**Edge case handling:**
- Division by zero protected with `+ 1` or `np.where(denominator == 0, 0, ...)` patterns
- Infinite values clipped to feature-appropriate maximum

---

## Step 3 — Feature Scaling

> Source: `src/engineering/preprocessor.py`

`StandardScaler` transforms each numerical feature to have **mean = 0** and **standard deviation = 1**.

```
z = (x - mean) / std
```

Applied to:
- All flow statistics (duration, bytes, packets, rates)
- All timing features (IAT mean, std, min, max)
- All derived ratio features

**Not applied to:**
- Binary/boolean flags (already in {0, 1})
- String-encoded categorical features (encoded separately)

---

## Step 4 — Normalization

> Source: `src/engineering/preprocessor.py`

`MinMaxScaler` bounds all features to the **[0, 1]** range:

```
x_scaled = (x - x_min) / (x_max - x_min)
```

Applied after StandardScaler to ensure compatibility with any threshold-based or probability-based models.

---

## Step 5 — Feature Selection

> Source: `src/engineering/feature_pipeline.py`

Removes features that do not contribute to classification. Two methods are used:

### Method A — Variance Threshold
Removes features with near-zero variance (constant or near-constant features).
```python
from sklearn.feature_selection import VarianceThreshold
selector = VarianceThreshold(threshold=0.01)
```

### Method B — Random Forest Feature Importance
During training, the Random Forest model (Phase 5) computes feature importance scores. Features with importance below a configurable threshold are dropped from future inference.

```python
importances = rf_model.feature_importances_
selected_features = [f for f, imp in zip(feature_names, importances) if imp > 0.005]
```

The final selected feature list is saved to `models/selected_features.json` and reused during inference.

---

## Categorical Encoding

Some features are strings and must be encoded before ML:

| Feature | Encoding Method |
|---|---|
| `tls_version` | Ordinal: SSLv3=0, TLS1.0=1, TLS1.1=2, TLS1.2=3, TLS1.3=4 |
| `protocol` | One-hot: TCP, UDP, ICMP |
| `alpn` | One-hot: h2=0, http/1.1=1, other=2, none=-1 |
| `cipher_is_weak` | Binary: 0 or 1 |
| `cert_self_signed` | Binary: 0 or 1 |

---

## Pipeline Orchestration

> Source: `src/engineering/feature_pipeline.py`

The full feature engineering pipeline is implemented as a **scikit-learn Pipeline** for reproducibility:

```python
from sklearn.pipeline import Pipeline

feature_pipeline = Pipeline([
    ('imputer',      SimpleImputer(strategy='median')),
    ('derived',      DerivedFeatureTransformer()),   # Custom transformer
    ('scaler',       StandardScaler()),
    ('normalizer',   MinMaxScaler()),
    ('selector',     SelectKBest(k=70)),
])
```

The fitted pipeline is serialized to `models/feature_pipeline.pkl` and reused during inference so that live traffic features are transformed identically to training data.

---

## Final Feature Vector

After all steps, each flow produces a fixed-dimension feature vector of approximately **60–80 features**, ready for the Random Forest classifier.

Example feature vector (simplified):
```
[0.73, 0.12, 0.95, 0.41, 0.08, 0.61, 0.82, 0.19, ...]
 │     │     │     │     │     │     │     │
 │     │     │     │     │     │     │     └── feature_N
 │     │     │     │     │     │     └──────── iat_cv
 │     │     │     │     │     └────────────── flow_symmetry
 │     │     │     │     └──────────────────── upload_ratio
 │     │     │     └────────────────────────── iat_mean (scaled)
 │     │     └──────────────────────────────── syn_rate
 │     └────────────────────────────────────── bytes_per_sec (scaled)
 └──────────────────────────────────────────── flow_duration (scaled)
```

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | Structured metadata dataset (~50 raw features, from Phase 3) |
| **OUTPUT** | ML feature vector (60–80 normalized features) |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Missing value imputation | `scikit-learn SimpleImputer` | Median / constant strategies |
| Feature scaling | `scikit-learn StandardScaler` | Zero-mean, unit-variance |
| Normalization | `scikit-learn MinMaxScaler` | [0, 1] range |
| Feature selection | `scikit-learn SelectKBest` | Information gain scoring |
| Derived features | Custom Python transformer | Ratio and combined features |
| Pipeline management | `scikit-learn Pipeline` | Reproducible fit/transform |
| Model persistence | `joblib` | Save/load fitted pipeline |
| Data manipulation | `pandas`, `numpy` | DataFrame and array operations |

---

## Deliverables

| File | Description |
|---|---|
| `src/engineering/preprocessor.py` | Imputer, scaler, normalizer setup and fit/transform |
| `src/engineering/derived_features.py` | Derived feature computation transformer |
| `src/engineering/feature_pipeline.py` | End-to-end scikit-learn Pipeline assembly |
| `src/engineering/__init__.py` | Module init and exports |
| `models/feature_pipeline.pkl` | Serialized fitted pipeline (produced during training) |
| `models/selected_features.json` | List of selected feature names |
