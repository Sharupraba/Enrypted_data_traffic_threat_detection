# Encrypted Traffic Threat Detection — Implementation Plan

> **Status:** Final reconciled plan (v2.0) — ready for development
> **Approach:** Non-intrusive, privacy-preserving encrypted traffic analysis using flow metadata, TLS fingerprinting, timing patterns, and ML — zero payload decryption.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Tech Stack](#3-tech-stack)
4. [Feature Engineering (100+ features)](#4-feature-engineering)
5. [Phase 1 — Data Collection & Traffic Capture](#phase-1-data-collection--traffic-capture)
6. [Phase 2 — Feature Engineering](#phase-2-feature-engineering)
7. [Phase 3 — ML Detection Engine](#phase-3-ml-detection-engine)
8. [Phase 4 — Threat Intelligence Integration](#phase-4-threat-intelligence-integration)
9. [Phase 5 — Alert Engine & Dashboard](#phase-5-alert-engine--dashboard)
10. [Phase 6 — Storage, Performance & Operations](#phase-6-storage-performance--operations)
11. [Phase 7 — Testing & Documentation](#phase-7-testing--documentation)
12. [Project Directory Structure](#project-directory-structure)
13. [Dataset Sources](#dataset-sources)
14. [Detection Coverage](#detection-coverage)
15. [Privacy & Compliance](#privacy--compliance)
16. [Milestones](#milestones)

---

## 1. System Overview

A non-intrusive network threat detection system that identifies malicious activity in **encrypted network traffic** using:

- **Flow-level statistics** — packet counts, byte ratios, rates, TCP flags
- **TLS metadata** — JA3/JA3S/JARM fingerprints, cipher suites, SNI entropy, certificate anomalies
- **Timing patterns** — IAT autocorrelation, FFT-based periodicity, burst detection
- **DNS correlation** — DGA scoring, NXDOMAIN rates, query entropy
- **Network graph features** — host connection degree, AS reputation, geolocation anomaly

**Privacy guarantee:** Zero payload inspection. GDPR/HIPAA-friendly. Fully on-premise.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          TRAFFIC SOURCES                             │
│    Live NIC capture (AF_PACKET / DPDK)  │  Offline PCAP upload      │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     PACKET CAPTURE LAYER                             │
│     libpcap / Scapy / NFStream / DPDK (high-throughput)             │
│   Raw packets → Session reconstruction → Bidirectional Flow records  │
│        5-tuple: src IP, dst IP, src port, dst port, protocol         │
│        Flow timeout: active 120s │ idle 30s                          │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    FEATURE EXTRACTION ENGINE                         │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │  Flow Stats │ │ TLS Metadata │ │   Timing /  │ │   DNS /     │  │
│  │             │ │ JA3,JARM,    │ │   IAT / FFT │ │   Graph /   │  │
│  │ Pkt counts, │ │ Cipher, SNI, │ │   Burst,    │ │   Network   │  │
│  │ Byte ratios,│ │ Cert, ALPN   │ │ Autocorr    │ │   Features  │  │
│  │ Flags, Ports│ │              │ │             │ │             │  │
│  └─────────────┘ └──────────────┘ └─────────────┘ └─────────────┘  │
│                       → 100+ features per flow                       │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      ML DETECTION ENGINE                             │
│  ┌─────────────────────────┐   ┌──────────────────────────────────┐  │
│  │   Classical ML Models   │   │       Deep Learning Models       │  │
│  │  - XGBoost / LightGBM  │   │  - 1D-CNN (packet sequences)    │  │
│  │  - Random Forest        │   │  - LSTM (IAT time series)       │  │
│  │  - Isolation Forest     │   │  - Autoencoder (zero-day)       │  │
│  └─────────────────────────┘   └──────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │     JA3 / JA3S / JARM Hash Lookup  (Redis — O(1))              │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                     ↓  ENSEMBLE SCORING  ↓                           │
│  Score = w1×AnomalyScore + w2×ClassifierConf                         │
│        + w3×JA3Match + w4×DNSScore + w5×ThreatIntelScore            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│               THREAT INTELLIGENCE ENRICHMENT LAYER                   │
│   IP Reputation: AbuseIPDB, VirusTotal, Shodan                      │
│   Domain Intel:  AlienVault OTX, Cisco Umbrella, Quad9              │
│   TLS:           Salesforce JA3 feed, JARM fingerprint DB            │
│   Certs:         crt.sh certificate transparency logs                │
│   MITRE ATT&CK:  TTP mapping per alert                              │
│   Cache:         Redis async — TTL 1 hour                            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                ALERT ENGINE & INVESTIGATION LAYER                    │
│  Severity: Info / Low / Medium / High / Critical                     │
│  Dedup: hash(src_ip, dst_ip, alert_type) — 5-minute window           │
│  SHAP explanations per alert (top-5 contributing features)           │
│  Output formats: JSON │ CEF (SIEM) │ Syslog                         │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        DASHBOARD (Web UI)                            │
│  Live Traffic Map │ Alert Feed │ Flow Inspector │ JA3 Explorer       │
│  Host Risk Score  │ Threat Timeline │ Detection Tuning               │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Packet capture | `libpcap`, `Scapy`, `NFStream`, `DPDK` | DPDK for ≥ 10 Gbps line rate |
| Feature extraction | `pandas`, `numpy`, `scipy` | Statistical + spectral features |
| TLS fingerprinting | `pyja3`, `dpkt`, custom JARM | JA3, JA3S, JARM hashes |
| Classical ML | `scikit-learn`, `XGBoost`, `LightGBM` | Fast inference, interpretable |
| Deep learning | `PyTorch` — LSTM, 1D-CNN, Autoencoder | Sequence + anomaly modeling |
| Explainability | `SHAP` | Per-alert feature importance |
| Backend API | `FastAPI` + WebSocket | Async, real-time alert streaming |
| Frontend | `React + Vite` + Recharts + Mapbox GL | Live dashboard |
| Hot storage | `Redis` | JA3 lookup, alert dedup, feature cache |
| Warm storage | `ClickHouse` / `TimescaleDB` | Time-series flow records |
| Cold storage | `MinIO` + Parquet | Long-term archive, retraining |
| Alerts DB | `PostgreSQL` | Alert management, case tracking |
| Message queue | `Apache Kafka` (prod) / Redis Streams (dev) | Flow event pipeline |
| Monitoring | `Prometheus` + `Grafana` | Operational observability |
| Orchestration | Docker Compose → Kubernetes (Helm) | Dev → Production path |

---

## 4. Feature Engineering

### 4.1 Flow-Level Statistical Features (~25 features)

| Feature | Description |
|---|---|
| `flow_duration` | Total flow duration in seconds |
| `total_fwd_packets` | Packets sent src → dst |
| `total_bwd_packets` | Packets sent dst → src |
| `total_fwd_bytes` / `total_bwd_bytes` | Byte volumes per direction |
| `flow_bytes_per_sec` | Total throughput |
| `flow_packets_per_sec` | Packet rate |
| `fwd_pkt_len_mean/std/min/max` | Packet size distribution (fwd) |
| `bwd_pkt_len_mean/std/min/max` | Packet size distribution (bwd) |
| `down_up_ratio` | bwd_bytes / fwd_bytes (exfil signal) |
| `fwd_bwd_packet_ratio` | Asymmetry indicator |
| `avg_packet_size` | Overall average |
| `byte_symmetry` | \|fwd − bwd\| / total (DDoS signal) |
| `header_payload_ratio` | Overhead vs. data ratio |
| `fwd_pkt_len_cv` | Coefficient of variation (C2: very low) |

### 4.2 TCP Flag Features (~10 features)

| Feature | Description |
|---|---|
| `fwd_syn/fin/rst/psh/ack/urg_count` | Per-flag packet counts (fwd) |
| `bwd_syn/fin/rst/psh_count` | Per-flag packet counts (bwd) |
| `syn_fin_ratio` | SYN-without-FIN = scan indicator |
| `rst_rate` / `psh_rate` | Flag rate per total packets |

### 4.3 TLS / SSL Fingerprinting Features (~15 features)

| Feature | Description |
|---|---|
| `ja3_hash` | MD5 of TLS ClientHello parameters |
| `ja3s_hash` | MD5 of TLS ServerHello parameters |
| `jarm_hash` | Active server TLS fingerprint |
| `tls_version` / `tls_version_risk` | Version ID + risk score (1.0=SSLv3, 0=TLS1.3) |
| `tls_is_deprecated` | Flag for TLS < 1.2 |
| `cipher_suite_id` / `cipher_is_weak` | Cipher ID + weakness flag |
| `cipher_supports_forward_secrecy` | ECDHE/DHE = 1, RSA = 0 |
| `sni_value` / `has_sni` | Server Name Indication |
| `sni_is_ip` | IP address in SNI = suspicious |
| `sni_label_entropy` | Shannon entropy of domain label (DGA) |
| `sni_digit_ratio` / `sni_consonant_ratio` | DGA domain character patterns |
| `alpn_protocol` / `alpn_is_suspicious` | Application protocol over TLS |
| `tls_extension_count` | Number of ClientHello extensions |
| `tls_risk_score` | Composite TLS risk (0.0–1.0) |

### 4.4 Certificate Features (~6 features)

| Feature | Description |
|---|---|
| `cert_self_signed` | Self-signed certificate flag |
| `cert_expired` | Certificate past expiry date |
| `cert_domain_mismatch` | SNI ≠ cert CN/SAN |
| `cert_days_to_expiry` | Remaining validity days |
| `cert_is_short_lived` | Valid < 30 days (fresh malware cert) |
| `cert_issuer_is_known_ca` | Unknown issuer = risk |

### 4.5 Timing / IAT Features (~20 features)

| Feature | Description |
|---|---|
| `flow_iat_mean/std/min/max` | Bidirectional IAT statistics (ms) |
| `fwd_iat_mean/std/min/max` | Forward direction IAT |
| `bwd_iat_mean/std/min/max` | Backward direction IAT |
| `iat_autocorrelation` | Periodicity strength (C2 beacon = high) |
| `iat_periodicity_score` | FFT dominant frequency power |
| `iat_dominant_frequency` | Main beacon interval |
| `burst_count` | Number of detected traffic bursts |
| `burst_avg_size` | Average packets per burst |
| `time_of_day_score` | Off-hours activity score (0–1) |
| `day_of_week` | Day encoding for temporal pattern |

### 4.6 Subflow / Burst Features (~8 features)

| Feature | Description |
|---|---|
| `subflow_fwd_packets` / `subflow_bwd_packets` | Packets per subflow |
| `subflow_fwd_bytes` / `subflow_bwd_bytes` | Bytes per subflow |
| `active_time_mean/std` | Active period statistics |
| `idle_time_mean/std` | Idle period statistics |

### 4.7 DNS Correlation Features (~8 features)

| Feature | Description |
|---|---|
| `dga_score` | N-gram entropy score of queried domain |
| `nxdomain_rate` | Fraction of NXDOMAIN responses for host |
| `dns_query_frequency` | Queries per unique domain |
| `dns_is_newly_registered` | Newly registered domain flag (threat intel) |
| `dns_record_type_entropy` | Unusual record types (TXT, NULL = tunneling) |
| `dns_response_size_anomaly` | Oversized DNS responses (tunneling) |
| `dns_subdomain_level` | Excessive subdomain depth = DGA |
| `dns_unique_domain_count` | Unique destinations per host per window |

### 4.8 Graph / Network Features (~8 features)

| Feature | Description |
|---|---|
| `host_connection_degree` | Unique destination count per source IP |
| `dst_port_rarity_score` | How unusual is the destination port |
| `dst_port_is_standard` | Port in {80, 443, 53, 22, 25} |
| `dst_port_is_high` | Ephemeral port (≥ 49152) |
| `as_reputation_score` | AS-level reputation from threat feeds |
| `geo_anomaly_score` | Deviation from historical destination baseline |
| `internal_fanout_degree` | Lateral movement indicator (internal hosts) |
| `conversation_symmetry` | Bidirectional flow balance score |

**Total: ~100 features per flow**

---

## Phase 1: Data Collection & Traffic Capture

**Goal:** Capture raw packet data without touching payload content.

### Components

#### Packet Capture Module (`src/capture/`)
- **Primary:** NFStream — reconstructs bidirectional flows with rich statistics, TLS dissection, and JA3 extraction
- **Fallback:** Scapy — cross-platform (Windows compatible), basic flow reconstruction
- Capture only headers: IP, TCP/UDP, TLS handshake metadata — **no payload stored**
- Support both live NIC capture and offline PCAP file analysis
- Output: per-flow Parquet records (batch) or JSON over Kafka/Redis (streaming)

#### Flow Aggregation
- 5-tuple bidirectional flows: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Active timeout: 120 seconds | Idle timeout: 30 seconds
- NFStream handles session reconstruction and bidirectional accounting natively

### Key Data Points Captured (No Payload)

| Field | Source |
|---|---|
| Flow duration | Timestamps |
| Packet inter-arrival times (IAT) | Packet metadata |
| Packet size distribution | Packet headers only |
| Bytes/sec, packets/sec | Computed |
| TCP flags sequence | TCP header |
| TLS version, cipher suite, SNI | TLS ClientHello |
| Certificate validity, self-signed flag | TLS handshake |
| JA3 / JA3S fingerprint | TLS ClientHello / ServerHello |
| DNS query patterns | DNS headers |
| ALPN protocol | TLS extension field |

### Deliverables
- `src/capture/live_capture.py` — Real-time NIC capture with graceful shutdown
- `src/capture/pcap_reader.py` — Offline PCAP reader (NFStream + Scapy fallback)

---

## Phase 2: Feature Engineering

**Goal:** Transform raw flow records into 100+ discriminative features per flow.

### Feature Pipeline
```
Raw PCAP / Live NIC
      ↓
[NFStream / Scapy]             ← Packet capture & session reconstruction
      ↓
[Flow Aggregator]              ← Bidirectional 5-tuple flow records
      ↓
[Feature Extractor]
  ├── flow_features.py         ← Stats, ratios, TCP flags, rates
  ├── tls_features.py          ← JA3, JA3S, JARM, ALPN, SNI entropy, cert anomalies
  ├── timing_features.py       ← IAT stats, FFT periodicity, autocorrelation, burst
  ├── dns_features.py          ← DGA score, NXDOMAIN rate, query entropy
  └── graph_features.py        ← Host degree, AS rep, geo anomaly, lateral movement
      ↓
[Normalizer / Scaler]          ← StandardScaler / MinMax per feature group
      ↓
[Feature Store]                ← Redis (hot, TTL 1h) + Parquet (cold archive)
```

### Deliverables
- `src/features/flow_features.py`
- `src/features/tls_features.py`
- `src/features/timing_features.py`
- `src/features/dns_features.py`
- `src/features/graph_features.py`
- `src/features/feature_pipeline.py`
- `notebooks/01_data_exploration.ipynb`
- `notebooks/02_feature_engineering.ipynb`

---

## Phase 3: ML Detection Engine

**Goal:** Classify flows as benign, suspicious, or malicious without payload inspection.

### 3.1 Anomaly Detection — Unsupervised
- **Isolation Forest** — detects statistical outliers across all flow features
- **LSTM Autoencoder** — learns normal traffic temporal patterns; high reconstruction error = anomaly
- Use case: zero-day threats, unknown malware families, insider threats

### 3.2 Supervised Classification
- **XGBoost / LightGBM** — fast, interpretable gradient boosting on tabular features
- **Random Forest** — robust to feature noise, handles class imbalance well
- Trained on: CICIDS2017, CIC-IDS-2018, CIC-IDS-2019, CTU-13, UNSW-NB15, ISCX-VPN-nonVPN
- Label classes: Benign, C2, Exfiltration, PortScan, DDoS, Botnet, Tunneling, Lateral Movement

### 3.3 TLS Fingerprint Matching
- JA3 / JA3S / JARM hash lookup against known malicious fingerprint databases
  - Salesforce JA3 feed, `trisulnetworks/ja3`, JARM fingerprint DB
- Real-time Redis hash map lookup — O(1) latency
- Returns confidence score: 1.0 (exact match) → 0.0 (clean)

### 3.4 Deep Sequence Models
- **1D-CNN** on packet size sequences — detects tunneling and abnormal protocol use
- **LSTM** on IAT time series — detects C2 beaconing (periodic callbacks)
- Input: sliding window of last N=50 packets per flow

### 3.5 Ensemble Threat Scoring
```
Final Score (0–100) =
  w1 × AnomalyScore           (Isolation Forest / Autoencoder)
+ w2 × ClassifierConfidence   (XGBoost / RF probability)
+ w3 × JA3MatchScore          (TLS fingerprint DB hit)
+ w4 × DNSRiskScore           (DGA + NXDOMAIN + entropy)
+ w5 × ThreatIntelScore       (IP/domain reputation enrichment)

Thresholds:
  ≥ 80 → Critical  |  ≥ 60 → High  |  ≥ 40 → Medium  |  ≥ 20 → Low
```

### 3.6 SHAP Explainability
- Per-alert SHAP values computed for every triggered detection
- Top-5 contributing features surfaced in the alert payload and dashboard
- Example: *"Alert because `iat_autocorrelation=0.94`, `ja3_match=True`, `sni_label_entropy=4.1`"*

### Deliverables
- `src/models/classical/random_forest.py`
- `src/models/classical/xgboost_model.py`
- `src/models/classical/isolation_forest.py`
- `src/models/deep/lstm_model.py`
- `src/models/deep/cnn_model.py`
- `src/models/deep/autoencoder.py`
- `src/models/tls_fingerprint.py`
- `src/models/ensemble.py`
- `src/models/trainer.py`
- `src/explainability/shap_explainer.py`
- `notebooks/03_model_training_classical.ipynb`
- `notebooks/04_model_training_deep.ipynb`
- `notebooks/05_ensemble_evaluation.ipynb`
- `notebooks/06_shap_explainability.ipynb`

---

## Phase 4: Threat Intelligence Integration

**Goal:** Enrich each detection with external context to reduce false positives.

### Intelligence Sources

| Source | Enrichment Type | API Method |
|---|---|---|
| AbuseIPDB | IP confidence score | REST |
| VirusTotal | IP / domain / hash reputation | REST |
| Shodan | Open ports, banners, CVEs per IP | REST |
| AlienVault OTX | Domain / IP threat pulses | REST |
| Cisco Umbrella | Domain risk classification | REST |
| Quad9 | DNS blocking signal | DNS query |
| Salesforce JA3 | Malicious JA3 hash feed | File sync |
| crt.sh | Certificate transparency history | REST |
| MITRE ATT&CK | TTP mapping per alert type | Local STIX bundle |

### Enrichment Pipeline
```
Detection fired
      ↓
Async Threat Intel Lookup (per IP / SNI / JA3 / cert)
      ↓
Redis cache hit? → Return cached result (TTL: 1h)
      ↓ (cache miss)
External API call → Store in Redis → Return
      ↓
MITRE ATT&CK TTP Tagging
      ↓
Enriched Alert → PostgreSQL Alert Store
```

### MITRE ATT&CK Mapping

| Technique | TTP ID | Detected By |
|---|---|---|
| C2 over Web Protocols | T1071.001 | LSTM + FFT (beaconing) |
| DNS Tunneling | T1071.004 | DNS entropy features |
| Encrypted Channel | T1573 | TLS risk + JA3 matching |
| Domain Generation Algorithm | T1568.002 | DGA scorer |
| Exfiltration Over C2 Channel | T1041 | Upload ratio + flow size |
| Remote Service Discovery | T1046 | Port scan features |
| Lateral Tool Transfer | T1570 | Graph fan-out features |

### Deliverables
- `src/threat_intel/ip_reputation.py`
- `src/threat_intel/domain_intel.py`
- `src/threat_intel/ja3_lookup.py`
- `src/threat_intel/cert_inspector.py`
- `src/threat_intel/intel_cache.py`
- `src/detection/mitre_mapper.py`

---

## Phase 5: Alert Engine & Dashboard

**Goal:** Surface actionable, analyst-ready insights with full context.

### Alert Engine
- **Severity tiers:** Info / Low / Medium / High / Critical
- **Deduplication:** Hash-based on `(src_ip, dst_ip, alert_type)` — 5-minute rolling window
- **Rate limiting:** Suppress repetitive low-confidence alerts (analyst fatigue control)
- **Allow-list management:** CIDR ranges, domain patterns, JA3 hash exceptions
- **Output formats:** JSON, CEF (SIEM integration), Syslog

### Dashboard Views (React + Vite + FastAPI)

| View | Description |
|---|---|
| **Live Traffic Map** | Real-time geo-map of flows, color-coded by risk score |
| **Alert Feed** | Live stream: severity badge, MITRE TTP, SHAP top features, timestamp |
| **Flow Inspector** | All 100+ feature values, model scores, raw packet timeline |
| **Host Risk Score** | Per-device rolling risk score (last 15-min / 1-hour window) |
| **JA3 Explorer** | Search TLS fingerprints; see all flows matching a given JA3 |
| **TLS Certificate View** | Flagged certs: self-signed / expired / mismatched / DGA domain |
| **Threat Timeline** | Heatmap of alert volume over time, filterable by category |
| **Detection Tuning** | Adjust per-model thresholds, manage allow-lists, suppress FPs |

### Deliverables
- `src/detection/detector.py`
- `src/detection/alert_engine.py`
- `src/api/main.py`
- `src/api/routes/capture.py`
- `src/api/routes/analysis.py`
- `src/api/routes/alerts.py`
- `src/api/routes/flows.py`
- `src/api/routes/models.py`
- `src/api/websocket.py`
- `frontend/` — React + Vite app with all 8 dashboard views

---

## Phase 6: Storage, Performance & Operations

**Goal:** Ensure the system runs sustainably at scale with full observability.

### Tiered Data Storage

| Tier | Technology | Retention | Purpose |
|---|---|---|---|
| **Hot** | Redis | 1 hour TTL | JA3 lookups, alert dedup, live feature cache |
| **Warm** | ClickHouse / TimescaleDB | 30 days | Time-series flow records, fast aggregation |
| **Cold** | MinIO + Parquet | Indefinite | Long-term archive, model retraining corpus |
| **Alerts** | PostgreSQL | Indefinite | Alert management, analyst notes, case tracking |

### Message Queue

| Environment | Technology | Topology |
|---|---|---|
| Development | Redis Streams | Single-node, zero dependencies |
| Production | Apache Kafka | Topics: `flows`, `alerts`, `enriched_alerts` |

### Performance Targets

| Metric | Target |
|---|---|
| Capture throughput (DPDK) | ≥ 10 Gbps |
| Capture throughput (AF_PACKET) | ≥ 1 Gbps |
| Flow classification latency | < 50 ms per flow |
| Alert generation latency | < 200 ms end-to-end |
| JA3 lookup latency | < 1 ms (Redis O(1)) |
| Threat intel enrichment | < 100 ms (async + cached) |
| Dashboard refresh | ≤ 1 second (WebSocket) |

### Monitoring & Observability
- **Prometheus** — metrics: flows/sec, alerts/sec, model inference latency, Kafka consumer lag
- **Grafana** — dashboards: system health, detection statistics, per-model accuracy drift
- **Structured logging** — JSON logs (structlog) — containerized stdout or ELK
- **Audit logging** — immutable log of all alert actions and config changes

### Deployment Path
```
Local Dev  →  Docker Compose  →  Kubernetes (Helm Charts)
```
- Role-based access: Analyst / Admin / Read-only
- IP anonymization option (last-octet masking) for GDPR/HIPAA
- Configurable data retention TTL per storage tier

### Deliverables
- `docker/Dockerfile.backend`
- `docker/Dockerfile.frontend`
- `docker/docker-compose.yml`
- `monitoring/prometheus.yml`
- `monitoring/grafana-dashboard.json`
- `k8s/` ─ Helm chart skeleton

---

## Phase 7: Testing & Documentation

**Goal:** Validate correctness, measure detection accuracy, package for handoff.

### Testing Strategy

| Test Type | Target | Tool |
|---|---|---|
| Unit | Feature extraction correctness | pytest |
| Unit | Model inference shape / output | pytest |
| Integration | API endpoints with sample PCAPs | pytest + httpx |
| Integration | WebSocket live alert stream | pytest-asyncio |
| System | Full pipeline: PCAP → alert | pytest |
| Performance | Classification latency benchmark | locust / time |

### Model Evaluation Targets

| Metric | Target |
|---|---|
| Weighted F1-score | ≥ 0.90 on CICIDS hold-out |
| ROC-AUC | ≥ 0.95 |
| False positive rate | ≤ 5% on benign traffic |
| Inference latency (p99) | < 50 ms |

### Manual Validation Checklist
- [ ] Upload a real malware PCAP from MalwareBazaar → verify alert fires correctly
- [ ] Inject synthetic C2 beaconing traffic → verify FFT periodicity score triggers
- [ ] Run live capture for 10 min on idle host → verify FP rate is < 5%
- [ ] Verify JA3 lookup fires for a known-bad fingerprint (e.g., Cobalt Strike)
- [ ] Confirm SHAP explanations describe the correct top features

### Deliverables
- `tests/test_features.py`
- `tests/test_models.py`
- `tests/test_api.py`
- `tests/fixtures/` — labeled sample PCAPs
- `README.md` — setup, usage, dataset download instructions

---

## Project Directory Structure

```
encrypted-traffic-threat-detection/
│
├── data/
│   ├── raw/                         # Raw PCAP files (git-ignored)
│   ├── processed/                   # Extracted flow CSVs / Parquet
│   └── datasets/                    # Public datasets (CICIDS, CTU-13, etc.)
│
├── src/
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── live_capture.py          # Real-time NIC capture (NFStream / AF_PACKET)
│   │   └── pcap_reader.py           # Offline PCAP analysis (NFStream + Scapy fallback)
│   │
│   ├── features/
│   │   ├── __init__.py
│   │   ├── flow_features.py         # Packet counts, byte ratios, TCP flags, rates
│   │   ├── tls_features.py          # JA3, JA3S, JARM, ALPN, SNI entropy, cert anomalies
│   │   ├── timing_features.py       # IAT stats, FFT periodicity, autocorrelation, burst
│   │   ├── dns_features.py          # DGA score, NXDOMAIN rate, query entropy
│   │   ├── graph_features.py        # Host degree, AS reputation, geo anomaly
│   │   └── feature_pipeline.py      # Full pipeline orchestration + normalization
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── classical/
│   │   │   ├── __init__.py
│   │   │   ├── random_forest.py
│   │   │   ├── xgboost_model.py
│   │   │   └── isolation_forest.py
│   │   ├── deep/
│   │   │   ├── __init__.py
│   │   │   ├── lstm_model.py        # LSTM for IAT time-series beaconing detection
│   │   │   ├── cnn_model.py         # 1D-CNN for packet size sequence classification
│   │   │   └── autoencoder.py       # LSTM Autoencoder for zero-day anomaly detection
│   │   ├── tls_fingerprint.py       # JA3 / JA3S / JARM hash matching engine
│   │   ├── ensemble.py              # Weighted ensemble scoring
│   │   └── trainer.py               # Model training orchestration
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── detector.py              # Main detection engine
│   │   ├── alert_engine.py          # Alert generation, dedup, rate limiting, allow-list
│   │   └── mitre_mapper.py          # ATT&CK TTP tagging per alert
│   │
│   ├── explainability/
│   │   ├── __init__.py
│   │   └── shap_explainer.py        # Per-alert SHAP feature importance
│   │
│   ├── threat_intel/
│   │   ├── __init__.py
│   │   ├── ip_reputation.py         # AbuseIPDB, VirusTotal, Shodan
│   │   ├── domain_intel.py          # AlienVault OTX, Cisco Umbrella, Quad9
│   │   ├── ja3_lookup.py            # Salesforce JA3 / JARM fingerprint DB
│   │   ├── cert_inspector.py        # crt.sh certificate history
│   │   └── intel_cache.py           # Redis async TTL cache
│   │
│   └── api/
│       ├── __init__.py
│       ├── main.py                  # FastAPI app entry point + middleware
│       ├── routes/
│       │   ├── __init__.py
│       │   ├── capture.py           # Start / stop live capture
│       │   ├── analysis.py          # PCAP upload & batch analysis
│       │   ├── alerts.py            # Alert CRUD + management
│       │   ├── flows.py             # Flow query + inspector
│       │   └── models.py            # Model management + threshold tuning
│       └── websocket.py             # WebSocket live alert stream
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── LiveTrafficMap.jsx
│   │   │   ├── AlertFeed.jsx
│   │   │   ├── FlowInspector.jsx
│   │   │   ├── HostRiskScore.jsx
│   │   │   ├── JA3Explorer.jsx
│   │   │   ├── ThreatTimeline.jsx
│   │   │   └── DetectionTuning.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_feature_engineering.ipynb
│   ├── 03_model_training_classical.ipynb
│   ├── 04_model_training_deep.ipynb
│   ├── 05_ensemble_evaluation.ipynb
│   └── 06_shap_explainability.ipynb
│
├── models/                          # Serialized trained models (.pkl / .pt)
│
├── tests/
│   ├── __init__.py
│   ├── test_features.py
│   ├── test_models.py
│   ├── test_api.py
│   └── fixtures/                    # Labeled sample PCAPs for testing
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
│
├── k8s/                             # Kubernetes Helm charts (production)
│
├── monitoring/
│   ├── prometheus.yml
│   └── grafana-dashboard.json
│
├── .env.example                     # Environment variable template
├── requirements.txt                 # Python dependencies
└── README.md
```

---

## Dataset Sources

| Dataset | Traffic Types | Size | Priority |
|---|---|---|---|
| **CICIDS 2017** | DDoS, PortScan, BotNet, Infiltration | ~2.8M flows | 🔴 High |
| **CIC-IDS 2018** | Brute Force, Infiltration, Web attacks | ~1.5M flows | 🔴 High |
| **CIC-IDS 2019** | Encrypted malicious flows (TLS-specific) | ~300K flows | 🔴 High |
| **CTU-13** | Botnet C2, P2P malware (encrypted) | ~1.5M flows | 🔴 High |
| **UNSW-NB15** | Fuzzers, Backdoors, Exploits, Shellcode | ~2.5M records | 🟡 Medium |
| **ISCX-VPN-nonVPN** | VPN vs. non-VPN encrypted traffic | ~150K flows | 🟡 Medium |
| **Malware Traffic Analysis** | Real malware PCAPs, labeled by family | Variable | 🟡 Medium |
| **Self-generated benign** | Normal enterprise HTTPS traffic baseline | Generated | 🟡 Medium |

Download destinations → `data/datasets/<dataset-name>/`

---

## Detection Coverage

| Threat Category | Primary Feature Signals | Detection Method | MITRE TTP |
|---|---|---|---|
| **C2 Beaconing** | IAT autocorrelation, fixed packet sizes, periodicity | LSTM + FFT | T1071.001 |
| **TLS Malware** | JA3/JA3S/JARM fingerprint match | Redis hash lookup | T1573 |
| **DNS Tunneling** | High-entropy DNS, TXT/NULL records, oversized responses | DNS feature scoring | T1071.004 |
| **DGA Malware** | Domain n-gram entropy, NXDOMAIN rate | DGA classifier (RF) | T1568.002 |
| **Data Exfiltration** | Upload ratio, large outbound flows, off-hours timing | XGBoost + Anomaly | T1041 |
| **Port Scanning** | High connection rate, low bytes/flow, many unique ports | Random Forest | T1046 |
| **DDoS** | Asymmetric packets, high PPS, SYN flood RST flags | Isolation Forest | — |
| **Protocol Tunneling** | Port/protocol mismatch, high byte entropy, ALPN anomaly | 1D-CNN | T1573 |
| **Lateral Movement** | Internal host fan-out, rare internal ports | Graph features + RF | T1570 |
| **Malware Staging** | Self-signed cert, DGA domain, cert age < 30 days | TLS features + RF | T1105 |
| **Zero-Day / Unknown** | High reconstruction error from normal traffic baseline | LSTM Autoencoder | — |

---

## Privacy & Compliance

| Control | Implementation |
|---|---|
| Zero payload inspection | Only headers and metadata processed — enforced at capture layer |
| IP anonymization | Last-octet masking option for GDPR/HIPAA deployments |
| Data retention | Configurable TTL per storage tier (Redis / ClickHouse / MinIO) |
| Role-based access | Analyst / Admin / Read-only — JWT-based RBAC |
| Audit logging | Immutable log of all alert actions and config changes |
| On-premise only | No traffic data leaves the network boundary |
| Allow-list management | CIDR, domain, JA3 hash exceptions for trusted traffic |

---

## Milestones

| Phase | Deliverable | Duration |
|---|---|---|
| **1** | Packet capture + flow aggregation pipeline (live + offline) | 2 weeks |
| **2** | Feature engineering — 100+ features + feature store | 2 weeks |
| **3** | ML models (classical + deep) + SHAP explainability + notebooks | 3 weeks |
| **4** | Threat intelligence integration + MITRE ATT&CK tagging | 1 week |
| **5** | Alert engine + FastAPI backend + React dashboard (8 views) | 2 weeks |
| **6** | Tiered storage + Kafka/Redis pipeline + Prometheus + Grafana + Docker | 2 weeks |
| **7** | Testing, benchmarking, full README, Helm charts | 2 weeks |
| **Total** | | **~14 weeks** |