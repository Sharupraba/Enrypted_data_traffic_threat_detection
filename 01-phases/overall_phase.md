# Encrypted Traffic Threat Detection — Architecture & Implementation Plan

> **Project Title:** Encrypted Traffic Threat Detection using Flow Metadata
> **Approach:** Privacy-preserving threat detection using flow metadata, timing patterns, packet characteristics, and TLS handshake metadata — zero payload decryption.
> **Architecture Version:** 2.0 (Simplified, Research-Grade)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Data Flow Summary](#3-data-flow-summary)
4. [Phase-by-Phase Breakdown](#4-phase-by-phase-breakdown)
   - [Phase 1 — Traffic Ingestion Layer](#phase-1--traffic-ingestion-layer)
   - [Phase 2 — Packet Parsing & Flow Generation](#phase-2--packet-parsing--flow-generation)
   - [Phase 3 — Metadata & Feature Extraction](#phase-3--metadata--feature-extraction)
   - [Phase 4 — Feature Engineering](#phase-4--feature-engineering)
   - [Phase 5 — Machine Learning Detection](#phase-5--machine-learning-detection)
   - [Phase 6 — Threat Intelligence Enrichment](#phase-6--threat-intelligence-enrichment)
   - [Phase 7 — Risk Scoring Engine](#phase-7--risk-scoring-engine)
   - [Phase 8 — Dashboard & Reporting](#phase-8--dashboard--reporting)
5. [Technology Stack](#5-technology-stack)
6. [Project Directory Structure](#6-project-directory-structure)
7. [Dataset Sources](#7-dataset-sources)
8. [Privacy Guarantee](#8-privacy-guarantee)
9. [Milestones](#9-milestones)

---

## 1. System Overview

A **privacy-preserving** network threat detection system that identifies malicious activity in encrypted network traffic **without decrypting any packet payloads**.

### What the System Analyzes

| Category | Features |
|---|---|
| **Flow Metadata** | Duration, packet count, byte volumes, packet/byte rates |
| **Packet Characteristics** | TCP flags, average packet size, header ratios |
| **Timing Patterns** | Inter-arrival times (IAT), burst detection, periodicity |
| **TLS Handshake Metadata** | JA3, JA3S, cipher suite, SNI, ALPN, certificate info |
| **DNS Features** | Domain entropy, query frequency, NXDOMAIN rate |

### Privacy Guarantee

> **Encrypted payloads are NEVER accessed, stored, or inspected at any stage.**
> All detection is performed exclusively on metadata.

---

## 2. Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║                  ENCRYPTED TRAFFIC THREAT DETECTION SYSTEM               ║
║                    Flow Metadata · Privacy-Preserving · Research Grade   ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — TRAFFIC INGESTION LAYER                                       │
│                                                                          │
│  ┌───────────────────────────┐    ┌──────────────────────────────────┐  │
│  │   Option A                │    │   Option B                       │  │
│  │   Live Traffic Monitoring │    │   PCAP Upload                    │  │
│  │                           │    │                                  │  │
│  │  • Network Interface      │    │  • .pcap / .pcapng Files         │  │
│  │  • Real-time Capture      │    │  • Offline Forensic Analysis     │  │
│  │  • Packet Headers Only    │    │  • Batch Processing              │  │
│  └─────────────┬─────────────┘    └────────────────┬─────────────────┘  │
│                │                                    │                    │
│                └──────────────┬─────────────────────┘                   │
│                               │  MERGE — Same Pipeline                  │
└───────────────────────────────┼─────────────────────────────────────────┘
                                │
                      OUTPUT: Raw Packet Stream
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — PACKET PARSING & FLOW GENERATION                              │
│                                                                          │
│  ┌────────────┐  ┌────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  Ethernet  │  │    IP      │  │  TCP / UDP  │  │  TLS Handshake  │  │
│  │   Header   │  │   Header   │  │   Header    │  │     Header      │  │
│  └────────────┘  └────────────┘  └─────────────┘  └─────────────────┘  │
│                                                                          │
│  Bidirectional Flow Builder  (5-tuple key)                               │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  src_ip | dst_ip | src_port | dst_port | protocol                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│  Flow Timeout:  Active = 120s  │  Idle = 30s                            │
│  Session Reconstruction: Bidirectional packet grouping                  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: Flow Records
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — METADATA & FEATURE EXTRACTION            🔒 NO PAYLOAD        │
│                                                                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────────┐    │
│  │   Flow      │ │    TCP      │ │   Timing    │ │  TLS Metadata  │    │
│  │  Features   │ │  Features   │ │  Features   │ │                │    │
│  │             │ │             │ │             │ │  JA3 / JA3S    │    │
│  │ Duration    │ │ SYN Count   │ │ Mean IAT    │ │  SNI / ALPN    │    │
│  │ Pkt Count   │ │ ACK Count   │ │ Std IAT     │ │  Cipher Suite  │    │
│  │ Bytes Sent  │ │ FIN Count   │ │ Min/Max IAT │ │  TLS Version   │    │
│  │ Bytes Recv  │ │ RST Count   │ │ Burst Count │ │  Certificate   │    │
│  │ Avg Pkt Sz  │ │ PSH Count   │ │             │ │                │    │
│  │ Pkts/sec    │ │             │ │             │ │                │    │
│  │ Bytes/sec   │ │             │ │             │ │                │    │
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────────┘    │
│                          ┌─────────────┐                                │
│                          │    DNS      │                                 │
│                          │  Features   │                                 │
│                          │             │                                 │
│                          │ Domain      │                                 │
│                          │ Entropy     │                                 │
│                          │ Query Freq  │                                 │
│                          │ NXDOMAIN    │                                 │
│                          └─────────────┘                                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: Structured Metadata Dataset
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 4 — FEATURE ENGINEERING                                           │
│                                                                          │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────────────┐  │
│  │ Missing Value   │  │ Feature Scaling  │  │ Normalization         │  │
│  │ Handling        │  │ (StandardScaler) │  │ (MinMaxScaler)        │  │
│  └─────────────────┘  └──────────────────┘  └───────────────────────┘  │
│  ┌─────────────────┐  ┌──────────────────┐                              │
│  │ Derived Features│  │ Feature Selection│                              │
│  │                 │  │ (SelectKBest /   │                              │
│  │ Upload Ratio    │  │  RandomForest    │                              │
│  │ Download Ratio  │  │  Importance)     │                              │
│  │ Packet Rate     │  │                  │                              │
│  │ Flow Symmetry   │  │                  │                              │
│  │ Byte Ratio      │  │                  │                              │
│  │ Header Ratio    │  │                  │                              │
│  └─────────────────┘  └──────────────────┘                              │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: ML Feature Vector
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 5 — MACHINE LEARNING DETECTION                                    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  PRIMARY MODEL: Random Forest Classifier                         │   │
│  │                                                                  │   │
│  │  • Classify traffic as Threat / Normal                           │   │
│  │  • Generate Confidence Score (0.0 – 1.0)                        │   │
│  │  • Feature importance for explainability                         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Example Output:                                                         │
│  ┌──────────────────────────────────┐                                   │
│  │  Classification : THREAT         │                                   │
│  │  Confidence     : 93%            │                                   │
│  └──────────────────────────────────┘                                   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: ML Prediction + Confidence Score
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 6 — THREAT INTELLIGENCE ENRICHMENT                                │
│  ⚠  This module DOES NOT detect threats.                                 │
│     It enriches detections already produced by the ML model.            │
│                                                                          │
│  ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────────┐   │
│  │  IP Reputation   │  │  Domain Reputation  │  │  JA3 Fingerprint │   │
│  │  Lookup          │  │  Lookup             │  │  Matching        │   │
│  │                  │  │                     │  │                  │   │
│  │  → AbuseIPDB     │  │  → VirusTotal       │  │  → JA3 Database  │   │
│  │  → VirusTotal    │  │                     │  │                  │   │
│  └──────────────────┘  └─────────────────────┘  └──────────────────┘   │
│                    ┌──────────────────────────┐                         │
│                    │ Certificate Reputation   │                         │
│                    │  → Validity Check        │                         │
│                    │  → Self-signed Flag      │                         │
│                    └──────────────────────────┘                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: Threat Context
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 7 — RISK SCORING ENGINE                                           │
│                                                                          │
│  Risk Score = f(ML Confidence, Threat Intelligence, TLS Metadata)       │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Score = (0.5 × ML Confidence)                                   │   │
│  │        + (0.3 × Threat Intel Score)                              │   │
│  │        + (0.2 × TLS Risk Score)                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Severity Levels:                                                        │
│  ┌────────┬──────────┬──────────┬──────────┬──────────┐                │
│  │  SAFE  │   LOW    │  MEDIUM  │   HIGH   │ CRITICAL │                │
│  │  0–20  │  21–40   │  41–60   │  61–80   │  81–100  │                │
│  └────────┴──────────┴──────────┴──────────┴──────────┘                │
│                                                                          │
│  Example:                                                                │
│  ┌────────────────────────────────┐                                     │
│  │  Risk Score : 91               │                                     │
│  │  Severity   : CRITICAL         │                                     │
│  └────────────────────────────────┘                                     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                      OUTPUT: Risk Score (0–100) + Severity Level
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 8 — DASHBOARD & REPORTING                                         │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │ System Overview  │  │ Traffic Source   │  │ Live Traffic Monitor │  │
│  │                  │  │                  │  │                      │  │
│  │ Total Flows      │  │ ○ Live Monitoring│  │ Src IP | Dst IP      │  │
│  │ Active Flows     │  │ ○ PCAP Upload    │  │ Protocol | Duration  │  │
│  │ Threat Count     │  │                  │  │ Risk Score           │  │
│  │ Detection Acc    │  │                  │  │                      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘  │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │ Threat Alerts    │  │ Flow Details     │  │ ML Analytics         │  │
│  │                  │  │                  │  │                      │  │
│  │ Threat Type      │  │ Flow Metadata    │  │ Feature Importance   │  │
│  │ Confidence       │  │ Timing Features  │  │ Confusion Matrix     │  │
│  │ Severity         │  │ TLS Metadata     │  │ ROC Curve            │  │
│  │ Timestamp        │  │                  │  │ Precision/Recall/F1  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘  │
│                                                                          │
│  Reports:  [ PDF ]  [ CSV ]  [ JSON ]                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow Summary

```
[Network Interface / PCAP File]
            │
            │  Raw Packets (headers only — payload excluded)
            ▼
[Packet Parser & Flow Builder]
            │
            │  Flow Records: 5-tuple bidirectional flows
            ▼
[Metadata & Feature Extractor]
            │
            │  Structured Metadata Dataset
            │  (Flow + TCP + Timing + TLS + DNS features)
            ▼
[Feature Engineering Pipeline]
            │
            │  ML-Ready Feature Vector
            ▼
[Random Forest Classifier]
            │
            │  Prediction: Threat / Normal
            │  Confidence Score: 0–100%
            ▼
[Threat Intelligence Enrichment]  ←— Only for flagged flows
            │
            │  Threat Context (IP, Domain, JA3, Certificate reputation)
            ▼
[Risk Scoring Engine]
            │
            │  Risk Score: 0–100
            │  Severity: Safe / Low / Medium / High / Critical
            ▼
[Dashboard & Reporting]
            │
            └── Live alerts, flow details, ML analytics, export
```

---

## 4. Phase-by-Phase Breakdown

### Phase 1 — Traffic Ingestion Layer

**Purpose:** Accept network traffic from two sources and merge into a single processing pipeline.

| Attribute | Details |
|---|---|
| **INPUT (Option A)** | Network interface (live real-time capture) |
| **INPUT (Option B)** | .pcap or .pcapng file (offline forensic analysis) |
| **Key Constraint** | Packet payload is NEVER captured or stored |
| **Merge Point** | Both paths produce identical raw packet objects |
| **OUTPUT** | Raw packet stream (headers only) |

**Technologies:**
- `Scapy` — live capture + PCAP parsing (cross-platform, Windows-compatible)
- `libpcap` / `WinPcap` / `Npcap` — underlying capture driver
- `pyshark` — Wireshark-based PCAP parsing (optional fallback)

---

### Phase 2 — Packet Parsing & Flow Generation

**Purpose:** Parse packet headers and build bidirectional network flows.

| Attribute | Details |
|---|---|
| **INPUT** | Raw packet stream |
| **Headers Parsed** | Ethernet, IP, TCP/UDP, TLS Handshake |
| **Flow Key** | `(src_ip, dst_ip, src_port, dst_port, protocol)` |
| **Active Timeout** | 120 seconds |
| **Idle Timeout** | 30 seconds |
| **Session Handling** | Bidirectional packet grouping per 5-tuple |
| **OUTPUT** | Bidirectional flow records |

**Technologies:**
- `Scapy` — packet parsing
- `dpkt` — fast header dissection
- `pandas` — flow record accumulation
- Custom `FlowTracker` class — timeout management, session reconstruction

---

### Phase 3 — Metadata & Feature Extraction

**Purpose:** Extract only metadata from flow records. Payload is never touched.

> 🔒 **Privacy Rule Enforced Here:** Only headers and handshake metadata are read. No payload bytes are accessed, decoded, or stored at any point.

#### Flow Features
| Feature | Description |
|---|---|
| `flow_duration` | Total duration in seconds |
| `total_fwd_packets` | Packets sent src → dst |
| `total_bwd_packets` | Packets sent dst → src |
| `bytes_sent` | Forward byte volume |
| `bytes_received` | Backward byte volume |
| `avg_packet_size` | Overall average packet size |
| `packets_per_sec` | Packet throughput rate |
| `bytes_per_sec` | Byte throughput rate |

#### TCP Features
| Feature | Description |
|---|---|
| `syn_count` | Number of SYN packets |
| `ack_count` | Number of ACK packets |
| `fin_count` | Number of FIN packets |
| `rst_count` | Number of RST packets |
| `psh_count` | Number of PSH packets |

#### Timing Features
| Feature | Description |
|---|---|
| `iat_mean` | Mean inter-arrival time |
| `iat_std` | Standard deviation of IAT |
| `iat_min` | Minimum IAT |
| `iat_max` | Maximum IAT |
| `burst_count` | Number of traffic bursts detected |

#### TLS Metadata
| Feature | Description |
|---|---|
| `tls_version` | TLS protocol version (1.0 / 1.1 / 1.2 / 1.3) |
| `cipher_suite` | Negotiated cipher suite identifier |
| `ja3_hash` | MD5 of TLS ClientHello parameters |
| `ja3s_hash` | MD5 of TLS ServerHello parameters |
| `alpn` | Application-layer protocol (h2, http/1.1, etc.) |
| `sni` | Server Name Indication (domain) |
| `cert_self_signed` | Certificate self-signed flag |
| `cert_expired` | Certificate past expiry |
| `cert_days_to_expiry` | Remaining validity days |

#### DNS Features *(if available)*
| Feature | Description |
|---|---|
| `dns_domain` | Queried domain name |
| `dns_query_frequency` | Queries per unique domain |
| `domain_entropy` | Shannon entropy of domain label (DGA signal) |
| `nxdomain_rate` | Fraction of failed DNS responses |

| Attribute | Details |
|---|---|
| **INPUT** | Bidirectional flow records |
| **OUTPUT** | Structured metadata dataset |

**Technologies:**
- `pyja3` — JA3 / JA3S hash computation
- `dpkt` / `cryptography` — TLS handshake parsing
- `numpy` / `pandas` — feature assembly
- `scipy` — statistical feature computation

---

### Phase 4 — Feature Engineering

**Purpose:** Transform extracted metadata into a clean, normalized feature vector ready for ML.

| Step | Tool | Description |
|---|---|---|
| Missing Value Handling | `pandas`, `SimpleImputer` | Fill NaN with median/zero |
| Feature Scaling | `StandardScaler` | Mean=0, Std=1 normalization |
| Normalization | `MinMaxScaler` | Bound features to [0, 1] |
| Derived Features | Custom Python | Computed ratios and derived signals |
| Feature Selection | `SelectKBest` / RF Importance | Remove low-information features |

**Derived Features Generated:**
| Feature | Formula |
|---|---|
| `upload_ratio` | `bytes_sent / (bytes_sent + bytes_received)` |
| `download_ratio` | `bytes_received / (bytes_sent + bytes_received)` |
| `packet_rate` | `total_packets / flow_duration` |
| `flow_symmetry` | `1 - abs(fwd_pkts - bwd_pkts) / total_pkts` |
| `byte_ratio` | `bytes_sent / bytes_received` |
| `header_ratio` | `header_bytes / total_bytes` |

| Attribute | Details |
|---|---|
| **INPUT** | Structured metadata dataset |
| **OUTPUT** | ML feature vector (60–80 normalized features) |

**Technologies:**
- `scikit-learn` — `StandardScaler`, `MinMaxScaler`, `SelectKBest`, `SimpleImputer`
- `pandas` / `numpy` — data transformation

---

### Phase 5 — Machine Learning Detection

**Purpose:** Primary threat detection. Classify each flow as Threat or Normal.

| Attribute | Details |
|---|---|
| **INPUT** | ML feature vector |
| **PRIMARY MODEL** | Random Forest Classifier |
| **Output — Class** | Threat / Normal |
| **Output — Score** | Confidence score (0.0 – 1.0, shown as %) |
| **Explainability** | Feature importance per prediction |

**Model Training Datasets:**
- CICIDS 2017 / 2018 / 2019
- UNSW-NB15
- CTU-13 (botnet C2 traffic)
- CIC-Bell-DNS-2021 (DNS-based threats)

**Performance Targets:**
| Metric | Target |
|---|---|
| Weighted F1-Score | ≥ 0.90 |
| ROC-AUC | ≥ 0.95 |
| False Positive Rate | ≤ 5% on benign traffic |
| Inference Latency | < 50 ms per flow |

**Example Output:**
```
Classification : THREAT
Confidence     : 93%
Top Features   : iat_autocorrelation, ja3_match, sni_entropy
```

**Technologies:**
- `scikit-learn` — RandomForestClassifier
- `joblib` — model serialization (.pkl)
- `SHAP` — per-prediction feature importance

---

### Phase 6 — Threat Intelligence Enrichment

**Purpose:** Enrich ML-confirmed detections with external context. This module does NOT perform threat detection.

> ⚠️ **IMPORTANT:** Threat Intelligence Enrichment only runs on flows that the ML model has already classified as threats. It does not generate new alerts.

| Enrichment Function | Source | Output |
|---|---|---|
| IP Reputation Lookup | AbuseIPDB, VirusTotal | Malicious IP confidence score |
| Domain Reputation Lookup | VirusTotal | Domain malice classification |
| JA3 Fingerprint Matching | JA3 Database (Salesforce / community) | Known-malicious TLS fingerprint match |
| Certificate Reputation | Self-signed check, expiry, domain mismatch | Certificate risk flags |

**Caching Strategy:**
- Results cached in-memory (Python `cachetools`) with 1-hour TTL
- Reduces API calls and latency for repeated IPs/domains

| Attribute | Details |
|---|---|
| **INPUT** | ML prediction (for flagged flows only) |
| **OUTPUT** | Threat context object |

**Technologies:**
- `requests` / `aiohttp` — REST API calls
- `cachetools` — local in-memory TTL cache
- `python-dotenv` — API key management

---

### Phase 7 — Risk Scoring Engine

**Purpose:** Combine ML confidence, threat intelligence, and TLS risk into a single actionable risk score.

**Scoring Formula:**
```
Risk Score (0–100) =
  (0.5 × ML Confidence %)
+ (0.3 × Threat Intel Score %)
+ (0.2 × TLS Risk Score %)
```

**Severity Mapping:**

| Score Range | Severity | Recommended Action |
|---|---|---|
| 0 – 20 | **SAFE** | No action required |
| 21 – 40 | **LOW** | Log and monitor |
| 41 – 60 | **MEDIUM** | Investigate |
| 61 – 80 | **HIGH** | Alert analyst |
| 81 – 100 | **CRITICAL** | Immediate response |

**Example:**
```
ML Confidence     : 93%  × 0.5 = 46.5
Threat Intel Score: 88%  × 0.3 = 26.4
TLS Risk Score    : 90%  × 0.2 = 18.0
─────────────────────────────────────
Risk Score        : 90.9 → 91
Severity          : CRITICAL
```

| Attribute | Details |
|---|---|
| **INPUT** | ML confidence + threat context + TLS metadata |
| **OUTPUT** | Risk score (0–100) + severity level |

**Technologies:**
- `Python` — scoring formula
- `numpy` — weighted arithmetic

---

### Phase 8 — Dashboard & Reporting

**Purpose:** Interactive web interface for monitoring, investigation, and reporting.

**Dashboard Sections:**

| Section | Content |
|---|---|
| **System Overview** | Total Flows, Active Flows, Threat Count, Detection Accuracy |
| **Traffic Source** | Toggle: Live Monitoring / PCAP Upload |
| **Live Traffic Monitor** | Table: Src IP, Dst IP, Protocol, Duration, Risk Score |
| **Threat Alerts** | Table: Threat Type, Confidence, Severity, Timestamp |
| **Flow Details** | Flow Metadata, Timing Features, TLS Metadata |
| **ML Analytics** | Feature Importance chart, Confusion Matrix, ROC Curve, Precision / Recall / F1 |
| **Reports** | Export: PDF, CSV, JSON |

| Attribute | Details |
|---|---|
| **INPUT** | Risk scores, alerts, flow records, ML metrics |
| **OUTPUT** | Interactive web dashboard + downloadable reports |

**Technologies:**
- `React + Vite` — frontend framework
- `FastAPI` — backend REST API + WebSocket
- `Recharts` — charts and graphs
- `pdfkit` / `reportlab` — PDF export
- `pandas` — CSV export
- WebSocket — real-time live feed

---

## 5. Technology Stack

| Phase | Component | Technology |
|---|---|---|
| **Phase 1** | Live Capture | `Scapy`, `Npcap` (Windows), `libpcap` (Linux) |
| **Phase 1** | PCAP Reading | `Scapy`, `pyshark` |
| **Phase 2** | Packet Parsing | `Scapy`, `dpkt` |
| **Phase 2** | Flow Tracking | Custom Python `FlowTracker` |
| **Phase 3** | TLS Parsing | `pyja3`, `dpkt`, `cryptography` |
| **Phase 3** | Feature Assembly | `pandas`, `numpy`, `scipy` |
| **Phase 4** | ML Preprocessing | `scikit-learn` |
| **Phase 4** | Data Manipulation | `pandas`, `numpy` |
| **Phase 5** | ML Model | `scikit-learn` RandomForest |
| **Phase 5** | Model Storage | `joblib` (.pkl files) |
| **Phase 5** | Explainability | `SHAP` |
| **Phase 6** | API Calls | `requests`, `aiohttp` |
| **Phase 6** | Caching | `cachetools` |
| **Phase 7** | Scoring | `Python`, `numpy` |
| **Phase 8** | Backend API | `FastAPI` |
| **Phase 8** | Frontend | `React`, `Vite`, `Recharts` |
| **Phase 8** | Real-time | WebSocket |
| **Phase 8** | Database | `SQLite` (local, simple) |
| **Phase 8** | PDF Export | `reportlab` |
| **All** | Environment | `python-dotenv`, `.env` |
| **All** | Config | `pyyaml`, `config.yaml` |
| **All** | Logging | `Python logging` module |

### What We Removed (and Why)

| Removed Component | Reason |
|---|---|
| Kafka | Not needed for a single-machine research system |
| MinIO | Local filesystem + SQLite is sufficient |
| ClickHouse | Overkill for research-scale data volumes |
| Redis | `cachetools` in-memory cache is sufficient |
| Prometheus + Grafana | Python `logging` + dashboard analytics covers it |
| Kubernetes + Helm | Not a production deployment — Docker Compose at most |
| Deep Learning (LSTM, CNN) | Random Forest is the primary model per project spec |
| DPDK | Not needed for research-grade capture |

---

## 6. Project Directory Structure

```
encrypted-traffic-threat-detection/
│
├── data/
│   ├── raw/                          # Raw PCAP files (git-ignored)
│   ├── processed/                    # Extracted flow CSV / Parquet
│   └── datasets/                     # Public datasets (CICIDS, UNSW-NB15, etc.)
│
├── src/
│   │
│   ├── ingestion/                    # PHASE 1
│   │   ├── __init__.py
│   │   ├── live_capture.py           # Real-time NIC capture (Scapy)
│   │   └── pcap_reader.py            # Offline PCAP reader (Scapy / pyshark)
│   │
│   ├── parsing/                      # PHASE 2
│   │   ├── __init__.py
│   │   ├── packet_parser.py          # Ethernet / IP / TCP / UDP / TLS header parsing
│   │   └── flow_builder.py           # Bidirectional flow tracker + timeout manager
│   │
│   ├── extraction/                   # PHASE 3
│   │   ├── __init__.py
│   │   ├── flow_features.py          # Duration, packet count, bytes, rates
│   │   ├── tcp_features.py           # SYN, ACK, FIN, RST, PSH counts
│   │   ├── timing_features.py        # IAT stats, burst detection
│   │   ├── tls_features.py           # JA3, JA3S, SNI, ALPN, cert, cipher, version
│   │   ├── dns_features.py           # Domain entropy, NXDOMAIN rate, query frequency
│   │   └── extractor.py              # Orchestrates all extraction modules
│   │
│   ├── engineering/                  # PHASE 4
│   │   ├── __init__.py
│   │   ├── preprocessor.py           # Missing value handling, scaling, normalization
│   │   ├── derived_features.py       # Upload ratio, download ratio, flow symmetry, etc.
│   │   └── feature_pipeline.py       # End-to-end feature engineering pipeline
│   │
│   ├── detection/                    # PHASE 5
│   │   ├── __init__.py
│   │   ├── model.py                  # Random Forest model wrapper (train + predict)
│   │   ├── trainer.py                # Model training on labelled datasets
│   │   └── explainer.py             # SHAP feature importance
│   │
│   ├── enrichment/                   # PHASE 6
│   │   ├── __init__.py
│   │   ├── ip_reputation.py          # AbuseIPDB, VirusTotal IP lookup
│   │   ├── domain_reputation.py      # VirusTotal domain lookup
│   │   ├── ja3_lookup.py             # JA3 fingerprint database matching
│   │   ├── cert_checker.py           # Certificate reputation checks
│   │   └── intel_cache.py            # In-memory TTL cache (cachetools)
│   │
│   ├── scoring/                      # PHASE 7
│   │   ├── __init__.py
│   │   └── risk_scorer.py            # Weighted risk score + severity classification
│   │
│   └── api/                          # PHASE 8 — Backend
│       ├── __init__.py
│       ├── main.py                   # FastAPI app entry point
│       ├── routes/
│       │   ├── capture.py            # Start / stop live capture
│       │   ├── upload.py             # PCAP file upload + analysis
│       │   ├── alerts.py             # Alert list, details, export
│       │   ├── flows.py              # Flow records, flow details
│       │   └── analytics.py          # ML metrics, feature importance
│       └── websocket.py              # WebSocket live alert + flow stream
│
├── frontend/                         # PHASE 8 — React Dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── SystemOverview.jsx
│   │   │   ├── TrafficSource.jsx
│   │   │   ├── LiveTrafficMonitor.jsx
│   │   │   ├── ThreatAlerts.jsx
│   │   │   ├── FlowDetails.jsx
│   │   │   ├── MLAnalytics.jsx
│   │   │   └── Reports.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── models/                           # Serialized trained models (.pkl)
│   └── random_forest.pkl
│
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_feature_engineering.ipynb
│   ├── 03_model_training.ipynb
│   └── 04_model_evaluation.ipynb
│
├── tests/
│   ├── __init__.py
│   ├── test_flow_builder.py
│   ├── test_feature_extraction.py
│   ├── test_model.py
│   ├── test_risk_scorer.py
│   └── fixtures/                     # Sample labeled PCAP files
│
├── config/
│   └── config.yaml                   # System configuration (timeouts, thresholds, etc.)
│
├── .env.example                      # API keys template (AbuseIPDB, VirusTotal)
├── requirements.txt                  # Python dependencies
├── README.md
└── docker-compose.yml                # Optional: containerize backend + frontend
```

---

## 7. Dataset Sources

| Dataset | Traffic Types | Priority |
|---|---|---|
| **CICIDS 2017** | DDoS, PortScan, BotNet, Infiltration | 🔴 High |
| **CIC-IDS 2018** | Brute Force, Web Attacks, Infiltration | 🔴 High |
| **CIC-IDS 2019** | Encrypted malicious flows (TLS-specific) | 🔴 High |
| **UNSW-NB15** | Fuzzers, Backdoors, Exploits, Shellcode | 🟡 Medium |
| **CTU-13** | Botnet C2, P2P malware (encrypted) | 🟡 Medium |
| **CIC-Bell-DNS-2021** | DNS tunneling, DGA | 🟡 Medium |

Download destination: `data/datasets/<dataset-name>/`

---

## 8. Privacy Guarantee

| Control | Enforcement |
|---|---|
| **Zero payload inspection** | Capture filters discard payload bytes at the packet capture layer |
| **Header-only parsing** | Parsers only access Ethernet, IP, TCP/UDP, and TLS handshake fields |
| **No payload storage** | Flow records store only computed statistics, never raw bytes |
| **TLS metadata only** | TLS parsing reads only the ClientHello / ServerHello header — never the encrypted application data |
| **On-premise only** | No traffic data is transmitted to external services (only hashes/IPs to threat intel APIs) |
| **IP anonymization option** | Last-octet masking configurable in `config.yaml` |

---

## 9. Milestones

| Phase | Deliverable | Duration |
|---|---|---|
| **1** | Traffic ingestion — live capture + PCAP reader | 1 week |
| **2** | Packet parser + bidirectional flow builder | 1 week |
| **3** | Metadata extraction (Flow + TCP + Timing + TLS + DNS) | 2 weeks |
| **4** | Feature engineering pipeline | 1 week |
| **5** | Random Forest model — train, evaluate, serialize | 2 weeks |
| **6** | Threat intelligence enrichment module | 1 week |
| **7** | Risk scoring engine | 0.5 week |
| **8** | FastAPI backend + React dashboard | 2 weeks |
| **Testing** | Unit tests, integration tests, model validation | 1 week |
| **Total** | | **~11.5 weeks** |