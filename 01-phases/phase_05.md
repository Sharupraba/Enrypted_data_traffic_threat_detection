# Phase 5: Alert Engine & Dashboard

> **Duration:** 2 weeks  
> **Status:** Not started  
> **Depends on:** Phase 3 (ensemble score), Phase 4 (enriched alert)  
> **Feeds into:** Phase 6 (Storage), Phase 8 (Retraining — analyst feedback)

---

## 1. Objective

Translate enriched ML detections into actionable, analyst-ready security alerts with minimal noise. Build a real-time, high-fidelity dashboard that accelerates investigation and reduces time-to-response.

The alert engine must solve two competing problems:
1. **Sensitivity:** Don't miss real threats.
2. **Specificity:** Don't flood analysts with false positives (alert fatigue kills security operations).

---

## 2. Alert Engine

### 2.1 Severity Classification

Final score → severity tier mapping:

| Score Range | Severity | Response Target | Color |
|---|---|---|---|
| 80 – 100 | CRITICAL | Immediate (< 15 min) | 🔴 Red |
| 60 – 79 | HIGH | Same session (< 1 hr) | 🟠 Orange |
| 40 – 59 | MEDIUM | Same day | 🟡 Yellow |
| 20 – 39 | LOW | Weekly review | 🔵 Blue |
| 0 – 19 | INFO | No action / logging only | ⚪ Gray |

### 2.2 Deduplication — Tiered by Severity

> **The 5-minute dedup window is too short for slow attacks.** A single dedup window suppresses fast-attack alert storms but misses slow attacks that deliberately operate across hours. Replace with severity-tiered dedup.

| Severity | Dedup Window | Rationale |
|---|---|---|
| CRITICAL / HIGH | 5 minutes | Fast attacks; alert every 5 min if still active |
| MEDIUM | 1 hour | Slow scans / low-rate exfil; suppress redundant alerts |
| LOW / INFO | 24 hours | Background noise; one daily summary |

**Dedup key:** `hash(src_ip, dst_ip, alert_category)` — intentionally excludes port and timestamp so recurring beaconing to the same destination is deduplicated correctly.

**Implementation:**
```python
dedup_ttl = {
    "CRITICAL": 300,    # 5 minutes
    "HIGH":     300,
    "MEDIUM":   3600,   # 1 hour
    "LOW":      86400,  # 24 hours
    "INFO":     86400,
}
dedup_key = f"dedup:{hash(src_ip + dst_ip + alert_category)}"
if redis.set(dedup_key, "1", ex=dedup_ttl[severity], nx=True):
    emit_alert()   # First occurrence — emit
# else: suppressed — increment dedup counter on existing alert
```

**Suppressed alert counting:** Even when an alert is suppressed by dedup, increment `dedup_count` on the original alert. This converts repeated suppressed events into a count field, preserving signal without flooding.

### 2.3 Rate Limiting

Global rate limiter caps total alerts per minute to prevent detection bursts from overwhelming the dashboard even when dedup fails:

```
Global:          max 100 alerts/minute
Per source IP:   max 10 alerts/minute
Per category:    max 20 alerts/minute per category
```

When rate limit is hit, a "Rate limit summary" meta-alert is emitted: "Suppressed N alerts from src_ip X in the last 60 seconds."

### 2.4 Allow-List (Alert-Level)

The primary allow-list is at the **capture layer** (Phase 1). This allow-list handles cases where an allow-listed host still generates valid flow records for non-allow-listed traffic.

Alert-level allow-list entries:
- `(src_ip, dst_ip, alert_category)` tuples — suppress this specific combination.
- Per-JA3-hash suppression — for known-safe internal tools with distinctive JA3 signatures.
- Time-scoped entries — e.g., suppress alerts from a specific IP during a maintenance window.

### 2.5 Alert Schema

```json
{
    "alert_id":           "uuid4",
    "created_at":         "ISO8601",
    "updated_at":         "ISO8601",
    "status":             "open | acknowledged | false_positive | true_positive | closed",

    "severity":           "CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "final_score_ml":     82.4,
    "final_score_enriched": 92.4,

    "alert_category":     "C2_BEACONING",
    "mitre_ttps":         ["T1071.001", "T1568.002"],

    "src_ip":             "10.0.0.42",
    "dst_ip":             "185.220.101.1",
    "src_port":           52341,
    "dst_port":           443,
    "protocol":           6,
    "flow_duration":      118.4,
    "sni":                "api.totally-not-malware.io",
    "ja3_hash":           "e7d705a3286e19ea42f587b344ee6865",
    "ja3s_hash":          "f4febc55ea12b31ae17cfb7e614afda1",

    "model_scores": {
        "isolation_forest": 0.72,
        "autoencoder":      0.81,
        "xgboost":          0.89,
        "cnn":              0.74,
        "lstm":             0.93,
        "ja3_match":        0.80,
        "dns_risk":         0.45
    },

    "shap_explanation": [
        {"feature": "iat_autocorrelation",  "value": 0.94, "contribution": "+42.3"},
        {"feature": "ja3_match_score",      "value": 1.0,  "contribution": "+18.1"},
        {"feature": "sni_label_entropy",    "value": 4.1,  "contribution": "+12.7"},
        {"feature": "fwd_pkt_len_cv",       "value": 0.02, "contribution": "+8.4"},
        {"feature": "cert_is_short_lived",  "value": 1,    "contribution": "+5.2"}
    ],
    "human_readable": "Traffic is highly periodic (beacon every ~62s), uses a known malicious TLS fingerprint, and connects to a high-entropy domain registered 3 days ago.",

    "enrichment": {
        "status": "complete | pending | failed",
        "ip_reputation": 0.92,
        "abuse_confidence": 87,
        "vt_malicious": 12,
        "vt_total": 72,
        "quad9_blocked": true,
        "domain_age_days": 3,
        "shodan_tags": ["tor-exit"]
    },

    "analyst_feedback": {
        "verdict": null,
        "analyst_id": null,
        "notes": null,
        "feedback_at": null
    },

    "dedup_count": 0,
    "dedup_key": "sha256:..."
}
```

### 2.6 Output Formats

| Format | Use Case |
|---|---|
| **JSON** | API responses, WebSocket streaming, internal storage |
| **CEF** | ArcSight SIEM integration |
| **Syslog (RFC 5424)** | Generic SIEM / log aggregator (Splunk, ELK) |
| **Webhook** | Push to Slack, PagerDuty, JIRA on HIGH/CRITICAL |

---

## 3. FastAPI Backend

### 3.1 REST API Routes

```
GET  /api/v1/alerts           → Paginated alert list (filter by severity, category, time)
GET  /api/v1/alerts/{id}      → Single alert with full details + SHAP
POST /api/v1/alerts/{id}/feedback → Analyst verdict (true/false positive)
PUT  /api/v1/alerts/{id}/status   → Change status (ack, close, escalate)

GET  /api/v1/flows            → Query flows (filter by IP, port, time, score)
GET  /api/v1/flows/{id}       → Single flow full feature vector
POST /api/v1/flows/upload     → Upload PCAP for offline analysis

POST /api/v1/capture/start    → Start live capture (Linux only)
POST /api/v1/capture/stop     → Stop live capture

GET  /api/v1/models           → List loaded models + versions
POST /api/v1/models/thresholds → Update ensemble score thresholds

GET  /api/v1/allowlist        → List current allow-list entries
POST /api/v1/allowlist        → Add entry
DELETE /api/v1/allowlist/{id} → Remove entry

GET  /api/v1/stats            → Dashboard stats (flows/min, alerts/min, top threats)
WS   /ws/alerts               → WebSocket: real-time alert stream
WS   /ws/traffic              → WebSocket: real-time flow rate stream
```

### 3.2 WebSocket Protocol

```json
// Alert stream message (WS /ws/alerts)
{
    "type": "alert",
    "data": { ... alert schema ... }
}

// Traffic stats message (WS /ws/traffic)
{
    "type": "traffic_stats",
    "data": {
        "flows_per_sec": 142,
        "bytes_per_sec": 18432000,
        "active_flows": 3821,
        "alerts_last_minute": 7,
        "top_src_ips": [...]
    }
}

// System message
{
    "type": "system",
    "data": {"message": "Learning mode active. 5 days remaining."}
}
```

---

## 4. Dashboard (React + Vite)

### 4.1 Views

#### Live Traffic Map
- Real-time geolocation of active flows on a Mapbox GL world map.
- Flows animated as arcs from src to dst country.
- Color: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🔵 BENIGN.
- Click any arc → opens Flow Inspector for that flow.

#### Alert Feed
- WebSocket-driven real-time stream of incoming alerts.
- Each alert card shows: severity badge, MITRE TTP tag, src/dst IP, score, top SHAP feature.
- One-click escalate, acknowledge, or mark false positive.
- Filter bar: severity, category, time range, src IP.

#### Flow Inspector
- Shows all 100+ feature values for a selected flow.
- SHAP waterfall chart: features sorted by contribution.
- `human_readable` explanation in a callout box.
- "Probe with JARM" button (analyst-initiated active investigation, admin only).
- Full packet timeline (IAT visualization) for the flow.

#### Host Risk Score
- Top 20 hosts by rolling risk score (last 15-min / 1-hour window).
- Per-host sparkline of risk score over time.
- Click host → filter Alert Feed and Flow Inspector to that src_ip.

#### JA3 Explorer
- Search by JA3 hash → see all flows in the database using that fingerprint.
- Shows whether the hash is in the known-malicious database.
- Timeline of when this fingerprint first appeared on the network.

#### TLS Certificate View
- Table of all certificates seen in TLS traffic, flagged by risk:
  - Self-signed, expired, domain mismatch, short-lived, unknown CA, mTLS detected.
- Click certificate → see all flows using that cert.

#### Threat Timeline
- Heatmap: alert volume over time (X = time, Y = threat category).
- Filterable by day/week/month.
- Overlays Learning Mode period (grayed out — no alerts generated during baseline).

#### Detection Tuning
- **Per-model weight sliders:** Adjust `w1`–`w7` in the ensemble formula.
- **Threshold sliders:** Adjust CRITICAL/HIGH/MEDIUM/LOW score cutoffs.
- **Dedup window overrides:** Override tiered dedup windows per category.
- **Allow-list manager:** Add/remove/search allow-list entries (IP/CIDR/domain/JA3).
- **Learning Mode toggle:** Manually enter/exit baseline learning mode.

### 4.2 Learning Mode Banner

During the 7-day bootstrap period (Phase 2, §2.7):
```
┌─────────────────────────────────────────────────────────────────────┐
│  ⏱ LEARNING MODE ACTIVE — Building traffic baseline.               │
│  Alerts are suppressed. Baseline complete in: 5 days, 14 hours.     │
│                          [Exit Learning Mode Early]                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. Analyst Feedback Loop (Critical for Phase 8)

Every alert must be actionable for the analyst **and** feed back into model improvement:

```
Alert displayed → Analyst reviews → Marks verdict:
  [✓ True Positive]  → Confirm threat: flow added to retraining corpus (positive class)
  [✗ False Positive] → Mark FP: flow added to retraining corpus (benign class)
                        + Auto-suggest allow-list rule if FP rate for this IP > 3
  [? Uncertain]       → Flag for senior analyst review
```

Analyst feedback is stored in the `analyst_feedback` block of the alert schema and in a dedicated `analyst_feedback` table in PostgreSQL. The Phase 8 retraining pipeline subscribes to this table.

---

## 6. Deliverables

| File | Description |
|---|---|
| `src/detection/detector.py` | Main detection orchestration |
| `src/detection/alert_engine.py` | Alert creation, tiered dedup, rate limiting, allow-list |
| `src/api/main.py` | FastAPI app with CORS, auth middleware |
| `src/api/routes/capture.py` | Live capture start/stop |
| `src/api/routes/analysis.py` | PCAP upload + batch analysis |
| `src/api/routes/alerts.py` | Alert CRUD + analyst feedback |
| `src/api/routes/flows.py` | Flow query + inspector |
| `src/api/routes/models.py` | Model management + threshold tuning |
| `src/api/websocket.py` | WebSocket live streams (alerts + traffic) |
| `frontend/` | Full React + Vite source (8 views + auth) |

---

## 7. Acceptance Criteria

- [ ] Alert dedup: MEDIUM severity alerts for same src/dst/category not repeated within 1 hour.
- [ ] CRITICAL alerts delivered to WebSocket within 200ms of ensemble scoring.
- [ ] Analyst feedback (TP/FP) stored correctly in PostgreSQL.
- [ ] Learning Mode banner visible on dashboard; no alerts generated during learning mode.
- [ ] Allow-list suppression verified: adding a rule stops alerts for that flow within 10 seconds.
- [ ] JARM probe button available only to admin role users.
- [ ] CEF output validated against ArcSight CEF spec.
- [ ] Rate limit (100 alerts/min global) enforced and tested.
