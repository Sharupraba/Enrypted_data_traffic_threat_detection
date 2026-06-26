# Phase 2: Feature Engineering

> **Duration:** 2 weeks  
> **Status:** Not started  
> **Depends on:** Phase 1 (flow records in Parquet)  
> **Feeds into:** Phase 3 (ML Detection Engine)

---

## 1. Objective

Transform raw flow records from Phase 1 into a structured, normalized, 100+ dimensional feature vector optimized for machine learning classifiers, deep sequence models, and anomaly detectors.

Every flow becomes a single row with deterministic, interpretable features. This phase is the most research-critical phase — the quality and correctness of features determines detection accuracy far more than model architecture choices.

---

## 2. Feature Groups

### 2.1 Flow-Level Statistical Features (~25 features)

These are aggregate statistics computed over all packets in a bidirectional flow.

| Feature | Formula / Source | Detection Signal |
|---|---|---|
| `flow_duration` | `last_seen - first_seen` (seconds) | Short flows at high rate = scanning |
| `total_fwd_packets` | Count of src→dst packets | |
| `total_bwd_packets` | Count of dst→src packets | |
| `total_fwd_bytes` | Sum of src→dst packet sizes | |
| `total_bwd_bytes` | Sum of dst→src packet sizes | |
| `flow_bytes_per_sec` | `total_bytes / flow_duration` | Spike = DDoS or burst exfil |
| `flow_packets_per_sec` | `total_packets / flow_duration` | |
| `fwd_pkt_len_mean/std/min/max` | Aggregate of fwd packet sizes | Fixed size = C2 beaconing |
| `bwd_pkt_len_mean/std/min/max` | Aggregate of bwd packet sizes | |
| `fwd_pkt_len_cv` | `std / mean` (coefficient of variation) | C2 malware: cv ≈ 0 (fixed-size packets) |
| `down_up_ratio` | `bwd_bytes / fwd_bytes` | High = download/C2 pull; Low = exfil |
| `fwd_bwd_packet_ratio` | `fwd_pkts / bwd_pkts` | Extreme asymmetry = DDoS |
| `avg_packet_size` | `total_bytes / total_packets` | |
| `byte_symmetry` | `|fwd_bytes - bwd_bytes| / total_bytes` | High = asymmetric attack traffic |
| `packet_symmetry` | `|fwd_pkts - bwd_pkts| / total_pkts` | |
| `encrypted_content_ratio` | `(total_bytes - est_header_bytes) / total_bytes` | **Note: see §2.1.1** |

#### 2.1.1 `encrypted_content_ratio` — Naming Clarification

> **Do not name this `header_payload_ratio`.** The system never inspects payloads. This feature estimates `(total_bytes - estimated_header_bytes) / total_bytes`, where `estimated_header_bytes = total_packets × avg_header_size (≈52 bytes for IP+TCP+options)`. The result is the **fraction of bytes that are encrypted TLS records** — not payload content. High values in very-small flows indicate header-heavy traffic (e.g., ACK-only keepalives). Rename to `encrypted_content_ratio` in all code and docs.

---

### 2.2 TCP Flag Features (~10 features)

| Feature | Detection Signal |
|---|---|
| `fwd_syn_count` | High SYN with no FIN = port scan |
| `bwd_syn_count` | SYN-ACK count (server responses) |
| `fwd_fin_count` | Normal session termination |
| `fwd_rst_count` | Resets — closed port responses or evasion |
| `fwd_psh_count` | Push flag — data transfer indicator |
| `fwd_ack_count` | Persistent ACK without data = keepalive |
| `fwd_urg_count` | URG flag — rare in normal traffic |
| `syn_fin_ratio` | `fwd_syn / max(fwd_fin, 1)` — scanner: >> 1 |
| `rst_rate` | `(fwd_rst + bwd_rst) / total_pkts` |
| `psh_rate` | `(fwd_psh + bwd_psh) / total_pkts` |

---

### 2.3 TLS / SSL Fingerprinting Features (~15 features)

> **JARM is an active technique and is NOT computed here.** See Phase 1, §6.3. All features in this group are derived passively from the TLS handshake captured in Phase 1.

| Feature | Source | Detection Signal |
|---|---|---|
| `ja3_hash` | MD5(TLS ClientHello params) | Malware tooling leaves unique JA3 |
| `ja3s_hash` | MD5(TLS ServerHello params) | C2 server framework fingerprint |
| `tls_version` | ClientHello/ServerHello version field | |
| `tls_version_risk` | Lookup table: SSLv3=1.0, TLS1.0=0.8, TLS1.2=0.1, TLS1.3=0.0 | |
| `tls_is_deprecated` | `1` if version < TLS 1.2 | |
| `cipher_suite_id` | First cipher in negotiation | |
| `cipher_is_weak` | Match against known weak suite list | |
| `cipher_supports_forward_secrecy` | ECDHE/DHE = 1, RSA key exchange = 0 | |
| `has_sni` | SNI extension present | Absent SNI is suspicious |
| `sni_is_ip` | IP address used as SNI | Highly suspicious |
| `sni_label_entropy` | Shannon entropy of leftmost domain label | High = DGA domain |
| `sni_digit_ratio` | Digits / total chars in label | High = DGA pattern |
| `sni_consonant_ratio` | Consonants / alpha chars | Low = DGA (missing vowels) |
| `alpn_protocol` | Application protocol in TLS extension | |
| `alpn_is_suspicious` | ALPN not in {h2, http/1.1, h3} over port 443 | Tunneling signal |
| `tls_extension_count` | Number of extensions in ClientHello | |
| `cert_self_signed` | Issuer == Subject in cert chain | |
| `cert_expired` | Certificate past NotAfter date | |
| `cert_domain_mismatch` | SNI not in cert SAN/CN | |
| `cert_days_to_expiry` | Days from capture to cert expiry | |
| `cert_is_short_lived` | `cert_days_to_expiry < 30` | Malware certs are fresh |
| `cert_issuer_is_known_ca` | Issuer in trusted CA list | Unknown CA = suspect |
| `cert_mutual_tls` | Client Certificate present in handshake | **mTLS is rare in normal client-server traffic; common in botnet C2 using cert-based auth** |
| `tls_risk_score` | Composite weighted score (0.0–1.0) | |

#### mTLS Detection

**Mutual TLS (mTLS)** occurs when both client and server present X.509 certificates. While mTLS is legitimate in zero-trust service meshes, it is **unusual in standard client-initiated HTTPS traffic**. Some botnets use mTLS as a C2 authentication mechanism — the bot presents a certificate to prove identity to the C2 server before receiving instructions. The `cert_mutual_tls` flag is computed by detecting a `CertificateRequest` message in the captured handshake.

---

### 2.4 Timing & IAT Features (~20 features)

Inter-Arrival Time (IAT) analysis is the most powerful signal for detecting **C2 beaconing**. Malware callbacks are typically scheduled (e.g., "phone home every 60 seconds"), creating a precisely periodic traffic pattern that FFT and autocorrelation can reliably detect.

| Feature | Description | Detection Signal |
|---|---|---|
| `flow_iat_mean/std/min/max` | Bidirectional IAT (ms) | |
| `fwd_iat_mean/std/min/max` | Forward IAT (ms) | |
| `bwd_iat_mean/std/min/max` | Backward IAT (ms) | |
| `iat_autocorrelation` | Lag-1 autocorrelation of IAT series | Near 1.0 = periodic (C2 beacon) |
| `iat_periodicity_score` | Power of dominant FFT frequency | High = regular beaconing |
| `iat_dominant_frequency` | Hz of peak FFT component | Beacon interval |
| `burst_count` | Number of idle-separated subflows | High = bursty C2 |
| `burst_avg_packets` | Mean packets per burst | |
| `time_of_day_hour` | UTC hour of flow start (0–23) | Off-hours = suspicious |
| `time_of_day_score` | Gaussian deviation from business hours | High = off-hours activity |
| `day_of_week` | 0=Monday … 6=Sunday | Weekend flows from corporate hosts |

**FFT-based Periodicity:**
> Collect the sequence of IATs for a flow. Apply a Fast Fourier Transform. If the dominant frequency explains more than 60% of the signal power (`iat_periodicity_score > 0.6`), the flow is exhibiting beaconing behavior. The dominant frequency (Hz) gives the beacon interval in seconds: `interval = 1 / iat_dominant_frequency`.

---

### 2.5 Subflow / Burst Features (~8 features)

> **Subflow definition:** A subflow is a contiguous segment of packets within a parent flow separated by an idle gap exceeding **1 second** (configurable). See Phase 1, §6.1.

| Feature | Description |
|---|---|
| `subflow_count` | Total number of subflows |
| `subflow_fwd_packets` | Mean packets per subflow (fwd direction) |
| `subflow_bwd_packets` | Mean packets per subflow (bwd direction) |
| `subflow_fwd_bytes` | Mean bytes per subflow (fwd direction) |
| `subflow_bwd_bytes` | Mean bytes per subflow (bwd direction) |
| `active_time_mean` | Mean duration of active (packet-sending) subflow periods |
| `active_time_std` | Standard deviation of active periods |
| `idle_time_mean` | Mean duration of idle gaps between subflows |
| `idle_time_std` | Standard deviation of idle gaps |

A **C2 beacon signature in subflow space:** `subflow_count ≈ flow_duration / beacon_interval`, `subflow_fwd_packets ≈ 1–3`, `idle_time_mean ≈ beacon_interval`, `idle_time_std ≈ 0` (very regular).

---

### 2.6 DNS Correlation Features (~8 features)

> **⚠️ Encrypted DNS Blind Spot (DoH/DoT)**
>
> These features assume DNS traffic is **visible in plaintext** on port 53. This assumption **fails** when:
> - The host uses **DNS-over-HTTPS (DoH)** — DNS becomes indistinguishable from HTTPS to a passive observer.
> - The host uses **DNS-over-TLS (DoT)** on port 853.
>
> Malware increasingly uses DoH resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`) specifically to bypass DNS-based detection.
>
> **Compensating controls:**
> 1. Flag all flows to port **853** (DoT) as requiring elevated scrutiny.
> 2. Flag HTTPS flows to IPs matching known DoH resolver IPs (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222`) — a malware process bypassing corporate DNS to a DoH resolver is inherently suspicious.
> 3. Cross-correlate TLS SNI against the queried domain from any plaintext DNS queries within the same `src_ip` window.

| Feature | Description | Detection Signal |
|---|---|---|
| `dga_score` | N-gram entropy of queried domain | High = DGA-generated domain |
| `nxdomain_rate` | NXDOMAIN responses / total queries (per src_ip, 5-min window) | High = DGA scanning |
| `dns_query_frequency` | Queries per unique domain name | |
| `dns_is_newly_registered` | Domain age < 30 days (from threat intel) | Malware uses fresh domains |
| `dns_record_type_entropy` | Entropy over record types queried | High TXT/NULL = DNS tunneling |
| `dns_response_size_anomaly` | Response bytes vs. query bytes ratio | Inflated responses = tunneling |
| `dns_subdomain_depth` | Depth of subdomain (dots count) | DGA: `a.b.c.d.evil.com` |
| `dns_doh_dot_flag` | Target is known DoH/DoT endpoint | Compensating control |

---

### 2.7 Graph / Network Features (~8 features)

> **⚠️ Bootstrap Period Required**
>
> Features `geo_anomaly_score`, `host_connection_degree`, and `time_of_day_score` **measure deviation from a learned baseline**. On first deployment, **no baseline exists**. These features will produce meaningless or extreme values for 7 days until the system learns the network's normal behavior patterns.
>
> **Deployment Procedure:**
> 1. Deploy the system in **Learning Mode** for 7 days (configurable).
> 2. In Learning Mode: all features are computed and logged, but **no alerts are generated**.
> 3. After 7 days: baselines are persisted to Redis and Learning Mode is disabled.
> 4. The dashboard shows a "Learning Mode" banner with a countdown timer.

| Feature | Description | Detection Signal |
|---|---|---|
| `host_connection_degree` | Unique destination IPs in last 5 minutes (per src_ip) | High = scanning |
| `host_connection_degree_baseline_delta` | Deviation from 7-day rolling average | Anomalous day = malware |
| `dst_port_rarity_score` | 1 - (P(dst_port) in last 24h for this src_ip) | Rare port = suspicious |
| `dst_port_is_standard` | 1 if dst_port in {80, 443, 53, 22, 25, 21, 8080} | |
| `dst_port_is_high` | 1 if dst_port >= 49152 | Ephemeral port = C2 common |
| `as_reputation_score` | AS-level reputation (0.0=trusted … 1.0=malicious) | High-risk AS |
| `geo_anomaly_score` | Deviation from historical geo-destination baseline | New country = alert |
| `internal_fanout_degree` | Unique internal IPs contacted (per src_ip, 5-min) | High = lateral movement |

---

## 3. Feature Pipeline Architecture

```
Phase 1 Output (Parquet / Redis Stream)
          ↓
  [flow_features.py]      → 25 statistical + 10 flag features
  [tls_features.py]       → 23 TLS/cert features
  [timing_features.py]    → 20 IAT + subflow features
  [dns_features.py]       → 8 DNS correlation features
  [graph_features.py]     → 8 network/graph features
          ↓
  [feature_pipeline.py]
    ├── Merge all feature dicts into single row
    ├── Impute missing values (median-fill for NFStream gaps)
    ├── Scale: StandardScaler for continuous, pass-through for flags/hashes
    ├── Validate: assert no NaN in scaled output
    └── Output: 100+ feature vector per flow
          ↓
  [Feature Store]
    ├── Redis (TTL 1h): for live inference pipeline
    └── Parquet: for model training and retraining corpus
```

---

## 4. Training Data Quality (Critical)

> **Training data quality is the most consequential decision of the entire project.** Models trained on poorly prepared data will fail silently on real traffic, reporting inflated accuracy on test sets while producing high false positive rates in production.

### 4.1 Dataset Issues to Know Before Training

| Dataset | Known Issues |
|---|---|
| **CICIDS2017** | Label noise due to traffic generator artifacts. Models learn generator fingerprints, not real attack patterns. Duplicate flows (same 5-tuple + timestamp). Up to 99%+ accuracy on test split → poor generalization. |
| **CICIDS2018** | Same generator; similar artifact issues. Use for ensemble diversity, not primary training. |
| **CTU-13** | Higher quality (real botnet traffic), but older (2011–2013). C2 protocols have evolved significantly. |
| **UNSW-NB15** | Synthetic environment with unrealistic benign traffic mix. |

### 4.2 Mandatory Pre-Training Validation Steps

Before any dataset is used for model training, run `notebooks/01_data_exploration.ipynb` which enforces:

1. **Deduplication by 5-tuple + timestamp:** Remove flows with identical `(src_ip, dst_ip, src_port, dst_port, protocol, first_seen_ms)`. CICIDS2017 has significant duplication.
2. **Class distribution audit:** Log class counts and ratios. CICIDS2017 can be >90% BENIGN. Apply SMOTE or class weights — do not downsample the minority class blindly.
3. **Feature artifact check:** Compute correlation of each feature with `source_file`. Any feature strongly correlated with the PCAP source file (not the label) is a dataset artifact, not a real signal. Drop it.
4. **Label noise estimate:** For CICIDS2017, cross-validate against CTU-13 labels for the same attack types. Suspicious discrepancy = label noise.

### 4.3 Dataset Split Strategy

| Dataset | Role |
|---|---|
| CICIDS2017 + CTU-13 | Training (after dedup + validation) |
| CICIDS2018 + UNSW-NB15 | Validation (hyperparameter tuning) |
| **CIC-IDS-2019** | **Held-out test set ONLY.** Never used for training or validation. Most relevant to this project (TLS-specific, nearest to real encrypted traffic). |
| Self-generated benign | Training + production FP tuning. Far more valuable than public benign datasets for reducing false positives on your own network. |

### 4.4 Self-Generated Benign Traffic

> This is **the most important dataset for production accuracy.** Public datasets model generic internet traffic. Your network (university/enterprise) has a specific pattern. 
> 
> **Collection procedure:**
> 1. Run the capture layer in a known-clean environment for 24–48 hours.
> 2. Label all flows `BENIGN`.
> 3. Mix 60% self-generated benign + 40% public benign as the benign class.
> 4. Re-evaluate FP rate on self-generated benign as the primary production quality metric.

---

## 5. Deliverables

| File | Description |
|---|---|
| `src/features/flow_features.py` | Flow stats + TCP flag features |
| `src/features/tls_features.py` | JA3/JA3S, SNI, cipher, cert, mTLS features |
| `src/features/timing_features.py` | IAT, FFT, subflow, burst, time-of-day features |
| `src/features/dns_features.py` | DGA, NXDOMAIN, record type, DoH/DoT flag |
| `src/features/graph_features.py` | Host degree, port rarity, AS rep, geo anomaly |
| `src/features/feature_pipeline.py` | Orchestration, imputation, scaling, output |
| `notebooks/01_data_exploration.ipynb` | Dataset quality audit, class distribution, dedup |
| `notebooks/02_feature_engineering.ipynb` | Feature distributions, correlation analysis, importance |

---

## 6. Acceptance Criteria

- [ ] Feature pipeline produces exactly N features (N ≥ 100) per flow record.
- [ ] No NaN values in scaled output (validated by assertion in pipeline).
- [ ] `encrypted_content_ratio` used everywhere (grep confirms no `header_payload_ratio` in codebase).
- [ ] JARM absent from all feature modules.
- [ ] `cert_mutual_tls` implemented and detects mTLS in test fixtures.
- [ ] `dns_doh_dot_flag` correctly flags flows to `1.1.1.1:443`, `8.8.8.8:443`, and `[...]:853`.
- [ ] Graph features produce `0.0` for all values during Learning Mode (7-day bootstrap).
- [ ] Data exploration notebook runs to completion on CICIDS2017 and reports dedup count and class imbalance.
- [ ] Scaler artifacts are saved to `models/scaler.pkl` for use in inference.
