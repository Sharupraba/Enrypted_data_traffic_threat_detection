# Phase 7 — Risk Scoring Engine

> **Position in Pipeline:** Receives enriched threat context from Phase 6 → Outputs Risk Score + Severity Level to Phase 8
> **Purpose:** Combine ML confidence, threat intelligence results, and TLS metadata into a single, normalized risk score and severity classification.

---

## Overview

Phase 7 is a deterministic scoring layer. It takes the three signal sources that have been computed in earlier phases and combines them using a weighted formula to produce:

1. A **Risk Score** from 0 to 100
2. A **Severity Level**: Safe, Low, Medium, High, or Critical

Phase 7 does not perform detection or enrichment. It aggregates and normalizes the outputs of Phases 5 and 6.

---

## Inputs

Phase 7 receives the enriched threat context produced by Phase 6:

```python
{
  "flow_id":                 str,
  "classification":          str,      # "THREAT" or "NORMAL"
  "confidence":              float,    # ML model confidence 0.0–1.0

  # From Phase 6 — Threat Intelligence Enrichment
  "ip_reputation_score":     int,      # 0–100
  "domain_reputation_score": int,      # 0–100
  "ja3_match":               bool,
  "ja3_match_score":         int,      # 0–100
  "cert_risk_score":         int,      # 0–100
  "enrichment_available":    bool,

  # TLS Metadata — from Phase 3 (passed through)
  "tls_version":             str | None,
  "cipher_suite":            str | None,
  "cert_self_signed":        bool | None,
  "cert_expired":            bool | None,
  "cert_domain_mismatch":    bool | None,
  "cert_is_short_lived":     bool | None,
  "sni":                     str | None,
  "ja3_hash":                str | None
}
```

---

## Scoring Formula

```
Risk Score (0–100) =
  (0.50 × ML Confidence Score)
+ (0.30 × Threat Intelligence Score)
+ (0.20 × TLS Risk Score)
```

All three components are individually normalized to a 0–100 scale before weighting.

---

## Component Calculations

### Component 1 — ML Confidence Score (weight: 50%)

```
ml_confidence_score = confidence × 100
```

`confidence` is the probability from Phase 5's `predict_proba` output for the THREAT class. A value of `1.0` maps to a score of `100`.

For flows classified as `NORMAL`, the ML Confidence Score is treated as `0` and no risk score is computed — the flow is scored as Safe.

---

### Component 2 — Threat Intelligence Score (weight: 30%)

Combines the enrichment signals from Phase 6:

```
threat_intel_score = max(
    ip_reputation_score,
    domain_reputation_score,
    ja3_match_score
)
```

If `enrichment_available` is `False` (APIs unavailable), this component defaults to `0` — neutral, not penalizing.

---

### Component 3 — TLS Risk Score (weight: 20%)

Computed from TLS metadata fields extracted in Phase 3 and passed through Phase 6:

| TLS Signal | Condition | Points Added |
|---|---|---|
| Weak TLS version | TLS version < 1.2 | +40 |
| Outdated TLS version | TLS version == 1.2 (acceptable) | +15 |
| Self-signed certificate | `cert_self_signed == True` | +30 |
| Expired certificate | `cert_expired == True` | +25 |
| Certificate domain mismatch | `cert_domain_mismatch == True` | +25 |
| Short-lived certificate | `cert_is_short_lived == True` | +20 |

```python
tls_risk_raw = sum of applicable point values (capped at 100)
tls_risk_score = min(tls_risk_raw, 100)
```

---

## Full Score Calculation Example

```
ML Confidence     : 93%  × 0.50 = 46.5
Threat Intel Score: 88%  × 0.30 = 26.4
TLS Risk Score    : 90%  × 0.20 = 18.0
─────────────────────────────────────────
Risk Score        : 90.9 → 91
Severity          : CRITICAL
```

---

## Severity Level Mapping

| Score Range | Severity | Recommended Action |
|---|---|---|
| 0 – 20 | **Safe** | No action required. Flow is benign. |
| 21 – 40 | **Low** | Log for audit. No immediate action. |
| 41 – 60 | **Medium** | Investigate. Check correlated flows. |
| 61 – 80 | **High** | Alert analyst. Prioritize for review. |
| 81 – 100 | **Critical** | Immediate response required. |

---

## Weight Adjustment for Missing Enrichment

When `enrichment_available` is `False`, the component weights are redistributed to avoid under-scoring due to API unavailability:

```
Adjusted weights when enrichment unavailable:
  ML Confidence     : 0.70 (was 0.50)
  Threat Intel Score: 0.00 (unavailable)
  TLS Risk Score    : 0.30 (was 0.20)
```

This ensures that the ML prediction still drives the final risk score even without enrichment context.

---

## Output

```python
{
  # All input fields passed through, plus:
  "risk_score":           int,    # 0–100 final score
  "severity":             str,    # "Safe" | "Low" | "Medium" | "High" | "Critical"

  # Score breakdown (for dashboard display and audit)
  "ml_contribution":      float,  # ML component × weight
  "ti_contribution":      float,  # Threat Intel component × weight
  "tls_contribution":     float,  # TLS component × weight

  # Component scores (before weighting)
  "ml_confidence_score":     int,
  "threat_intel_score":      int,
  "tls_risk_score":          int
}
```

---

## Normal Flow Handling

Flows classified as `NORMAL` by Phase 5 do NOT go through Phase 6 enrichment and produce a minimal Phase 7 output:

```python
{
  "flow_id":     str,
  "risk_score":  0,
  "severity":    "Safe"
}
```

These are recorded but do not generate alerts.

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | Enriched threat context (from Phase 6, for THREAT flows) or ML prediction (for NORMAL flows) |
| **OUTPUT** | Risk Score (0–100) + Severity Level (Safe / Low / Medium / High / Critical) |

---

## Module: `src/scoring/risk_scorer.py`

```python
def compute_tls_risk_score(tls_fields: dict) -> int:
    """
    Evaluates TLS metadata fields and returns a risk score 0–100.
    Uses additive point system capped at 100.
    """

def compute_threat_intel_score(enrichment: dict) -> int:
    """
    Derives a single 0–100 score from the enrichment signals.
    Returns 0 if enrichment_available is False.
    """

def compute_risk_score(context: dict) -> dict:
    """
    Main entry point. Takes enriched threat context from Phase 6.
    Returns the final risk score, severity level, and component breakdown.
    """
```

---

## Configuration (config.yaml)

```yaml
risk_scoring:
  weights:
    ml_confidence:    0.50
    threat_intel:     0.30
    tls_risk:         0.20

  # Weights used when enrichment is unavailable
  fallback_weights:
    ml_confidence:    0.70
    threat_intel:     0.00
    tls_risk:         0.30

  severity_thresholds:
    safe:     20
    low:      40
    medium:   60
    high:     80
    critical: 100

  tls_risk_points:
    tls_version_below_1_2:    40
    tls_version_1_2:          15
    cert_self_signed:         30
    cert_expired:             25
    cert_domain_mismatch:     25
    cert_short_lived:         20
```

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Scoring formula | Python | Deterministic weighted arithmetic |
| Numerical operations | `numpy` | Weighted sum, clipping |
| Output formatting | Python `dataclass` | Structured output dict |

---

## Deliverables

| File | Description |
|---|---|
| `src/scoring/risk_scorer.py` | Risk score computation and severity classification |
| `src/scoring/__init__.py` | Module init and exports |
