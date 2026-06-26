# Phase 7: Testing & Documentation

> **Duration:** 2 weeks | **Depends on:** All previous phases complete | **Feeds into:** Phase 8

---

## 1. Objective

Validate detection accuracy, system correctness, latency, and compliance. Produce a complete test suite and all user-facing documentation needed for handoff and deployment.

---

## 2. Testing Strategy

### 2.1 Test Pyramid

```
         ┌──────────────────────────┐
         │   System / E2E Tests     │  5%  — Full PCAP → alert pipeline
         ├──────────────────────────┤
         │  Integration Tests       │  25%  — API, DB, WebSocket, enrichment
         ├──────────────────────────┤
         │  Unit Tests              │  70%  — Features, models, alert engine
         └──────────────────────────┘
```

### 2.2 Unit Tests (`tests/test_features.py`)

Feature extraction tests validate correctness using hand-crafted synthetic flow records with known expected outputs:

```python
def test_fwd_pkt_len_cv_low_for_c2_beacon():
    """C2 beacons use fixed packet sizes → CV should be near 0."""
    flow = {"fwd_pkt_len_mean": 64.0, "fwd_pkt_len_std": 0.5, ...}
    features = compute_flow_features(flow)
    assert features["fwd_pkt_len_cv"] < 0.1

def test_sni_is_ip_detected():
    flow = {"requested_server_name": "185.220.101.1", ...}
    features = compute_tls_features(flow)
    assert features["sni_is_ip"] == 1

def test_doh_dot_flag_for_cloudflare():
    flow = {"dst_ip": "1.1.1.1", "dst_port": 443, ...}
    features = compute_dns_features(flow)
    assert features["dns_doh_dot_flag"] == 1

def test_encrypted_content_ratio_not_called_header_payload():
    """Enforce naming convention — no 'header_payload' in feature dicts."""
    flow = make_dummy_flow()
    features = compute_flow_features(flow)
    assert "header_payload_ratio" not in features
    assert "encrypted_content_ratio" in features
```

### 2.3 ML Model Tests (`tests/test_models.py`)

```python
def test_isolation_forest_trained_on_benign_only():
    """Anomaly models must only see benign training data."""
    trainer = IsolationForestTrainer()
    assert trainer.training_labels == {"BENIGN"}

def test_xgboost_inference_latency():
    """p99 inference time must be < 50ms."""
    model = load_model("xgboost")
    batch = generate_feature_vectors(1000)
    latencies = [timer(model.predict, [row]) for row in batch]
    assert np.percentile(latencies, 99) < 0.050  # 50ms

def test_ensemble_score_range():
    """Ensemble score must always be 0–100."""
    for _ in range(1000):
        score = ensemble.score(random_feature_vector())
        assert 0.0 <= score <= 100.0

def test_cic_ids_2019_not_in_training_data():
    """Enforce held-out test set is never trained on."""
    training_files = trainer.list_training_sources()
    assert not any("cic-ids-2019" in f.lower() for f in training_files)
```

### 2.4 Integration Tests (`tests/test_api.py`)

```python
async def test_pcap_upload_generates_alert():
    """Upload a known-malicious PCAP → confirm alert is created."""
    with open("tests/fixtures/cobalt_strike_beacon.pcap", "rb") as f:
        response = await client.post("/api/v1/flows/upload", files={"file": f})
    assert response.status_code == 200
    # Wait for async detection pipeline
    await asyncio.sleep(2)
    alerts = await client.get("/api/v1/alerts?severity=HIGH,CRITICAL")
    assert len(alerts.json()["items"]) > 0

async def test_websocket_alert_stream():
    """Alerts transmitted over WebSocket within 200ms."""
    async with websockets.connect("ws://localhost:8000/ws/alerts") as ws:
        inject_flow(malicious_flow)
        msg = await asyncio.wait_for(ws.recv(), timeout=0.2)
        assert json.loads(msg)["type"] == "alert"

async def test_analyst_feedback_stored():
    alert_id = create_test_alert()
    await client.post(f"/api/v1/alerts/{alert_id}/feedback",
                      json={"verdict": "false_positive"})
    feedback = db.query("SELECT * FROM analyst_feedback WHERE alert_id = $1", alert_id)
    assert feedback["verdict"] == "false_positive"
```

### 2.5 Fixture PCAPs (`tests/fixtures/`)

| File | Content | Expected Outcome |
|---|---|---|
| `cobalt_strike_beacon.pcap` | Cobalt Strike C2 beaconing | CRITICAL alert, T1071.001 |
| `port_scan_nmap.pcap` | nmap SYN port scan | HIGH alert, T1046 |
| `dns_tunneling_iodine.pcap` | iodine DNS tunneling tool | HIGH alert, T1071.004 |
| `benign_chrome_https.pcap` | Normal Chrome HTTPS browsing | No alert |
| `dga_malware_sample.pcap` | DGA domain C2 communication | HIGH alert, T1568.002 |
| `mutual_tls_botnet.pcap` | mTLS C2 authentication | MEDIUM alert |
| `dot_853_traffic.pcap` | DNS-over-TLS on port 853 | MEDIUM alert (DoT flag) |

### 2.6 Security / Compliance Tests

```python
def test_no_payload_captured():
    """Verify no payload bytes in flow records."""
    flow_record = capture_single_flow(test_pcap)
    assert "payload" not in flow_record
    assert "content" not in flow_record
    assert "body" not in flow_record

def test_jarm_absent_from_passive_capture():
    """JARM must not appear in capture or feature modules."""
    result = subprocess.run(
        ["grep", "-r", "jarm", "src/capture/", "src/features/"],
        capture_output=True
    )
    assert result.returncode != 0, "JARM found in passive module — remove it"

def test_allowlist_prevents_inference():
    """Allow-listed flows must produce zero alerts."""
    add_to_allowlist(cidr="10.0.0.0/8")
    inject_flow({"src_ip": "10.0.0.42", "dst_ip": "185.220.101.1"})
    alerts = get_alerts(src_ip="10.0.0.42")
    assert len(alerts) == 0
```

---

## 3. Model Evaluation Report

Run on **CIC-IDS-2019 held-out test set** (never seen during training). Report:

| Metric | Target | Actual |
|---|---|---|
| Weighted F1-score | ≥ 0.82 | TBD |
| Macro ROC-AUC | ≥ 0.95 | TBD |
| False Positive Rate (benign class) | ≤ 5% | TBD |
| Inference latency p99 | < 50ms | TBD |
| Per-class F1 (C2_BEACONING) | ≥ 0.80 | TBD |
| Per-class F1 (PORT_SCAN) | ≥ 0.90 | TBD |

Additionally: Evaluate on **self-generated benign traffic** for production FP rate estimation. This is the most operationally meaningful accuracy metric.

---

## 4. Manual Validation Checklist

- [ ] `cobalt_strike_beacon.pcap` → CRITICAL alert, SHAP shows `iat_autocorrelation` as top feature.
- [ ] `benign_chrome_https.pcap` → Zero alerts.
- [ ] `dot_853_traffic.pcap` → MEDIUM alert with `dns_doh_dot_flag=1`.
- [ ] `mutual_tls_botnet.pcap` → Alert contains `cert_mutual_tls=1`.
- [ ] Allow-listing `10.0.0.42` → zero subsequent alerts from that IP.
- [ ] Learning Mode: enable → inject malicious flow → confirm zero alerts generated.
- [ ] JARM probe button → confirm active probe to test IP returns a hash.
- [ ] Analyst marks an alert as False Positive → flow appears in `s3://ettd-cold/retraining/confirmed_fp/` within 1 hour.

---

## 5. Documentation

| Document | Content |
|---|---|
| `README.md` | Quick start, architecture overview, dataset links, API key setup |
| `docs/deployment.md` | Docker Compose + Kubernetes step-by-step |
| `docs/dataset_guide.md` | Download instructions for all 6 datasets + pre-processing steps |
| `docs/feature_dictionary.md` | All 100+ features: name, formula, interpretation |
| `docs/analyst_guide.md` | Dashboard walkthrough, alert triage workflow, how to read SHAP |
| `docs/api_reference.md` | Auto-generated OpenAPI spec from FastAPI |
| `CHANGELOG.md` | Version history |

---

## 6. CI/CD (GitHub Actions)

```yaml
on: [push, pull_request]
jobs:
  test:
    - pytest tests/ --cov=src --cov-report=xml
    - assert coverage > 80%
  lint:
    - ruff check src/
    - mypy src/ --strict
  compliance:
    - grep -r "jarm" src/capture/ src/features/ && exit 1    # JARM must not appear
    - grep -r "header_payload_ratio" src/ && exit 1           # Naming enforcement
    - grep -r "payload" src/capture/ && exit 1               # No payload access
```

---

## 7. Deliverables

| File | Description |
|---|---|
| `tests/test_features.py` | Feature extraction unit tests |
| `tests/test_models.py` | Model correctness + performance tests |
| `tests/test_api.py` | API + WebSocket integration tests |
| `tests/test_security.py` | Compliance / no-payload / JARM tests |
| `tests/fixtures/` | 7 labeled sample PCAPs |
| `README.md` | Final project README |
| `docs/` | All documentation files |
| `.github/workflows/ci.yml` | CI/CD pipeline |

---

## 8. Acceptance Criteria

- [ ] `pytest tests/` passes with ≥ 80% coverage.
- [ ] CI pipeline runs on every push and blocks merge on test failure.
- [ ] JARM compliance test in CI (grep-based, blocks merge if JARM in passive modules).
- [ ] Naming convention test blocks merge if `header_payload_ratio` found.
- [ ] Model evaluation notebook runs end-to-end on CIC-IDS-2019 without touching training data.
- [ ] All 7 fixture PCAPs produce the expected alert outcomes.
- [ ] `docs/feature_dictionary.md` covers all 100+ features.
