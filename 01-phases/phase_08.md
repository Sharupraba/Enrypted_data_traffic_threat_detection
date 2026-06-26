# Phase 8: Model Retraining & Continuous Improvement

> **Duration:** 2 weeks (initial setup) + ongoing  
> **Status:** Not started  
> **Depends on:** Phase 5 (analyst feedback), Phase 6 (cold storage corpus)  
> **New phase** — Added based on production accuracy drift concerns

---

## 1. Why This Phase Exists

> **Without a retraining pipeline, model accuracy degrades silently.**

Production network baselines shift over weeks. Browser TLS fingerprints change with every Chrome release. Attackers update C2 tooling regularly to avoid detection. Within 4–8 weeks of deployment, a static model begins accumulating false positives (legitimate traffic that looks like old malware patterns) and false negatives (new malware variants not seen during training).

The retraining pipeline closes the feedback loop:

```
Analyst marks alert → FP/TP corpus grows → Trigger retraining →
New model candidate trained → A/B compared against current → 
Promoted or rejected → Dashboard updated
```

---

## 2. Analyst Feedback Corpus

Every analyst verdict written in Phase 5 (True Positive / False Positive) is:
1. Stored in the `analyst_feedback` PostgreSQL table.
2. The corresponding flow's feature vector is exported to the appropriate MinIO path:
   - TP verdict → `s3://ettd-cold/retraining/confirmed_tp/`
   - FP verdict → `s3://ettd-cold/retraining/confirmed_fp/`

**Feedback quality controls:**
- Minimum 50 new feedback entries required before triggering a retraining run.
- Auto-suggest allow-list rule when ≥ 3 FPs share the same `(src_ip, alert_category)` combination.
- Analyst feedback requires `analyst` or `admin` role. `read-only` role cannot submit verdicts.

---

## 3. Automated Retraining Trigger

Retraining is triggered when **any one** of these conditions fires:

| Trigger | Threshold | Monitor |
|---|---|---|
| Analyst FP rate (7-day rolling) | > 8% | PostgreSQL query on `analyst_feedback` |
| Ensemble score drift (benign flows) | Rolling mean shifts > 5 points in 7 days | Prometheus metric |
| New analyst feedback volume | ≥ 50 new verdicts since last retrain | PostgreSQL count |
| Manual trigger | Admin clicks "Retrain Now" in dashboard | API endpoint |
| Scheduled | Weekly (every Sunday at 02:00 UTC) | Cron job |

The trigger writes to `stream:retrain_jobs` in Redis (or Kafka topic `retraining`).

---

## 4. Retraining Pipeline

```
Trigger Event
      ↓
[Corpus Builder]
  ├── Load base training data (CICIDS2017 + CTU-13 from cold storage)
  ├── Load confirmed_tp/ flows → add as malicious class samples
  ├── Load confirmed_fp/ flows → add as benign class samples
  ├── Load recent self-generated benign from s3://ettd-cold/retraining/benign/
  ├── Dedup by 5-tuple + timestamp (always re-run dedup)
  └── Compute class weights for new distribution
      ↓
[Trainer]
  ├── Retrain XGBoost with new corpus
  ├── Retrain Isolation Forest on benign-only subset
  ├── Fine-tune LSTM and CNN (transfer learning from previous weights, 10 epochs)
  └── Skip Autoencoder full retrain (expensive) — fine-tune only if FP rate > 15%
      ↓
[Evaluator]
  ├── Evaluate new model on CIC-IDS-2019 held-out (the ONLY test set)
  ├── Compare new model vs current production model on same test set
  ├── If new_f1 >= current_f1 - 0.02 → PASS (allow 2% degradation tolerance)
  └── If new_f1 < current_f1 - 0.02 → FAIL (reject, alert ops team)
      ↓
[A/B Comparison] (7-day parallel run) 
  ├── Route 10% of live flows through new model candidate
  ├── Compare FP rate and alert volume vs production model
  ├── Dashboard shows A/B split metrics
  └── Admin approves or rejects promotion after review
      ↓
[Promotion]
  ├── New model saved to models/ with semantic version bump
  ├── Model metadata JSON updated
  ├── Previous model archived (not deleted — rollback available)
  ├── Audit log records: promoted_by, old_model_id, new_model_id, timestamp
  └── Prometheus metric: ettd_model_version_info updated
```

---

## 5. Model Versioning

```
models/
├── xgboost_v1.0.0.pkl         ← Initial production model
├── xgboost_v1.0.0.meta.json
├── xgboost_v1.1.0.pkl         ← First retrained model
├── xgboost_v1.1.0.meta.json
└── ...

Meta JSON format:
{
    "model_id": "xgboost_v1.1.0",
    "trained_on": ["CICIDS2017", "CTU-13", "analyst_feedback_2026-08"],
    "training_date": "2026-08-15",
    "trigger_reason": "FP rate exceeded 8% threshold",
    "corpus_stats": {
        "total_samples": 412000,
        "confirmed_tp_added": 284,
        "confirmed_fp_added": 1102,
        "benign_self_generated": 52000
    },
    "evaluation": {
        "held_out_f1": 0.89,
        "held_out_roc_auc": 0.96,
        "fp_rate_on_benign": 0.031,
        "previous_model_f1": 0.87
    },
    "feature_list_hash": "sha256:...",
    "scaler_path": "models/scaler_v1.1.pkl",
    "status": "production | candidate | archived"
}
```

**Rollback:** If a newly promoted model causes FP spike, the admin can roll back to the previous version from the dashboard in one click. The old model `.pkl` is never deleted until manually purged.

---

## 6. Baselining Mode Refresh

Every 30 days, the system re-runs the 7-day baseline learning period for graph features (`geo_anomaly_score`, `host_connection_degree_baseline_delta`). This keeps baselines current as the network evolves (new servers onboarded, user location patterns changing).

The 30-day refresh does not suppress alerts — it runs in the background and updates baselines in Redis without entering full Learning Mode.

---

## 7. Notebook

`notebooks/07_model_retraining.ipynb` — Manual walkthrough of the retraining process for data scientists:
1. Load fresh corpus (base + feedback).
2. Data validation and dedup.
3. Training and evaluation comparison.
4. SHAP comparison: do the important features change between model versions?
5. Decision: promote or reject the new model candidate.

---

## 8. Dashboard — Retraining Tab (Admin only)

| View | Content |
|---|---|
| Retraining Status | Current model version, last retrain date, next scheduled retrain |
| Trigger History | Log of all retrain events and outcomes |
| A/B Comparison | Live FP rate and alert volume: current vs candidate model |
| Corpus Stats | TP/FP feedback count since last retrain, FP rate trend |
| Promote / Rollback | One-click model promotion or rollback to previous version |

---

## 9. Deliverables

| File | Description |
|---|---|
| `src/retraining/corpus_builder.py` | Loads base + feedback data, deduplicates, weights |
| `src/retraining/retraining_worker.py` | Orchestrates trainer + evaluator + versioning |
| `src/retraining/ab_comparator.py` | Live A/B traffic routing and metric collection |
| `src/retraining/model_registry.py` | Version management, promotion, rollback |
| `src/api/routes/retraining.py` | API endpoints for retraining management |
| `notebooks/07_model_retraining.ipynb` | Manual retraining workflow |

---

## 10. Acceptance Criteria

- [ ] Analyst FP verdict → corresponding flow in `s3://ettd-cold/retraining/confirmed_fp/` within 1 hour.
- [ ] Retraining trigger fires when 7-day FP rate > 8% (tested with synthetic feedback injection).
- [ ] A/B routing sends exactly 10% of flows to candidate model (validated by Prometheus counters).
- [ ] Model promotion recorded in audit log with before/after model IDs.
- [ ] Rollback restores previous model weights and updates Prometheus model version metric.
- [ ] Retraining pipeline never touches CIC-IDS-2019 (CI grep check).
- [ ] `notebooks/07_model_retraining.ipynb` runs end-to-end without error.
