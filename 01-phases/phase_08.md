# Phase 8 — Dashboard & Reporting

> **Position in Pipeline:** Final phase — consumes risk scores, alerts, flow records, and ML analytics from all prior phases
> **Purpose:** Provide an interactive web interface for real-time monitoring, threat investigation, and report generation.

---

## Overview

Phase 8 is the user-facing layer of the system. It presents detection results, flow details, ML analytics, and risk information through an interactive dashboard.

The dashboard supports both traffic input modes from Phase 1 — users can switch between **Live Traffic Monitoring** and **PCAP File Upload** from within the interface.

---

## Dashboard Sections

### Section 1 — System Overview

A summary header that displays the current system state at a glance.

| Metric | Description |
|---|---|
| **Total Flows** | Total number of flows processed in the current session |
| **Active Flows** | Flows currently being tracked (live mode only) |
| **Threat Count** | Number of flows classified as threats |
| **Detection Accuracy** | Current model F1 score from training metrics |

---

### Section 2 — Traffic Source Selection

Allows the user to switch between the two traffic input methods from Phase 1.

| Control | Behavior |
|---|---|
| **Live Monitoring** (radio button) | Activates live capture interface — interface selector appears |
| **PCAP Upload** (radio button) | Activates file upload form — `.pcap` / `.pcapng` accepted |

When **Live Monitoring** is selected:
- A dropdown lists available network interfaces (returned by `list_interfaces()` from Phase 1).
- **Start / Stop / Pause** buttons control the capture session.

When **PCAP Upload** is selected:
- A file upload input accepts `.pcap` and `.pcapng` files (max size: 500 MB).
- A progress indicator shows parsing and analysis progress.
- Results appear in the flow table once processing completes.

---

### Section 3 — Live Traffic Monitor

A real-time flow table that updates continuously during live capture or displays results after PCAP processing.

| Column | Source |
|---|---|
| **Src IP** | Phase 2 flow record |
| **Dst IP** | Phase 2 flow record |
| **Protocol** | Phase 2 flow record |
| **Duration** | Phase 3 `flow_duration` |
| **Risk Score** | Phase 7 output |
| **Severity** | Phase 7 severity level |

Rows are color-coded by severity:
- **Critical** — Red
- **High** — Orange
- **Medium** — Yellow
- **Low** — Blue
- **Safe** — Green

In live mode, the table is updated via **WebSocket** push from the backend.

---

### Section 4 — Threat Alerts

A filtered view showing only flows that have been classified as threats. Alerts are sorted by Risk Score (highest first).

| Column | Source |
|---|---|
| **Threat Type** | ML top feature signals from Phase 5 |
| **Confidence** | ML confidence score (Phase 5) |
| **Risk Score** | Phase 7 |
| **Severity** | Phase 7 severity level |
| **Timestamp** | Flow start time (Phase 2) |
| **Flow ID** | Unique flow identifier |

Each alert row is clickable and opens the **Flow Details** panel.

---

### Section 5 — Flow Details

A detail panel shown when the user selects a specific flow from the Live Traffic Monitor or Threat Alerts table.

**Flow Metadata section:**

| Field | Source |
|---|---|
| `src_ip`, `dst_ip` | Phase 2 |
| `src_port`, `dst_port` | Phase 2 |
| `protocol` | Phase 2 |
| `flow_duration` | Phase 3 |
| `total_packets`, `bytes_sent`, `bytes_received` | Phase 3 |

**Timing Features section:**

| Field | Source |
|---|---|
| `iat_mean`, `iat_std`, `iat_min`, `iat_max` | Phase 3 |
| `burst_count` | Phase 3 |

**TLS Metadata section (if available):**

| Field | Source |
|---|---|
| `tls_version`, `cipher_suite` | Phase 3 |
| `ja3_hash`, `ja3s_hash` | Phase 3 |
| `sni`, `alpn` | Phase 3 |
| Certificate info (self-signed, expired, mismatch) | Phase 3 |

**Risk Breakdown section:**

| Field | Source |
|---|---|
| `risk_score`, `severity` | Phase 7 |
| `ml_contribution`, `ti_contribution`, `tls_contribution` | Phase 7 score breakdown |

**Top Features (SHAP) section:**

Displays the top 5 features that most influenced the ML prediction, from Phase 5's SHAP explainer.

---

### Section 6 — ML Analytics

Static charts computed from the trained model, displayed for reference.

| Chart | Content |
|---|---|
| **Feature Importance** | Bar chart of top-20 features by Random Forest importance |
| **Confusion Matrix** | 2×2 matrix: TP, FP, FN, TN |
| **ROC Curve** | True Positive Rate vs False Positive Rate |
| **Precision / Recall / F1** | Scalar metric display |

Data source: `models/training_metrics.json` — pre-computed during model training in Phase 5.

---

### Section 7 — Report Export

Allows the user to export data from the current session.

| Format | Contents |
|---|---|
| **PDF** | Summary report: system overview, threat alert table, top risk flows, ML metrics |
| **CSV** | All flow records from the current session (one row per flow) |
| **JSON** | Full structured output — all flow records with all feature and scoring fields |

Exports are generated server-side and downloaded by the browser.

---

## Backend API (FastAPI)

The dashboard communicates with a **FastAPI** backend that exposes the detection pipeline.

### REST Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/interfaces` | List available network interfaces |
| `POST` | `/api/capture/start` | Start live capture on a selected interface |
| `POST` | `/api/capture/stop` | Stop live capture |
| `POST` | `/api/capture/pause` | Pause live capture |
| `POST` | `/api/upload` | Upload a PCAP file for offline analysis |
| `GET` | `/api/flows` | Retrieve all flow records from the current session |
| `GET` | `/api/flows/{flow_id}` | Retrieve details for a specific flow |
| `GET` | `/api/alerts` | Retrieve all THREAT-classified flows |
| `GET` | `/api/analytics` | Retrieve ML training metrics |
| `GET` | `/api/reports/pdf` | Download PDF report |
| `GET` | `/api/reports/csv` | Download CSV export |
| `GET` | `/api/reports/json` | Download JSON export |

### WebSocket Endpoint

| Path | Event Types | Frequency |
|---|---|---|
| `ws://localhost:8000/ws/stream` | `new_flow`, `new_alert`, `stats_update` | Per-flow (live mode) |

Each `new_flow` event pushes the full scored flow record to the dashboard in real time.

---

## Frontend (React + Vite)

The dashboard is a single-page application built with React and Vite.

### Component Structure

```
frontend/src/
├── components/
│   ├── SystemOverview.jsx        # Section 1 — stats header
│   ├── TrafficSource.jsx         # Section 2 — Live / PCAP toggle and controls
│   ├── LiveTrafficMonitor.jsx    # Section 3 — flow table with severity rows
│   ├── ThreatAlerts.jsx          # Section 4 — filtered alert table
│   ├── FlowDetails.jsx           # Section 5 — detail panel for selected flow
│   ├── MLAnalytics.jsx           # Section 6 — model performance charts
│   └── Reports.jsx               # Section 7 — export buttons
├── hooks/
│   └── useWebSocket.js           # WebSocket subscription for live updates
├── api/
│   └── client.js                 # REST API helper functions
├── App.jsx
└── main.jsx
```

### Key Libraries

| Library | Purpose |
|---|---|
| `React 18` | UI components and state management |
| `Vite` | Build tool and dev server |
| `Recharts` | Feature importance chart, ROC curve, confusion matrix |
| `axios` | REST API HTTP requests |
| `native WebSocket` | Live traffic stream connection |

---

## Database (SQLite)

Flow records and alert data are stored locally in SQLite for the current session.

| Table | Contents |
|---|---|
| `flows` | All processed flow records with all metadata and scores |
| `alerts` | Subset of flows with `classification = THREAT` |

SQLite is sufficient for research-scale and single-machine operation. No external database is required.

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | Risk scores + severity levels (Phase 7), flow metadata (Phase 2/3), ML metrics (Phase 5) |
| **OUTPUT** | Interactive web dashboard, real-time WebSocket stream, downloadable PDF/CSV/JSON reports |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Backend API | `FastAPI` | REST endpoints + WebSocket server |
| Frontend framework | `React 18` + `Vite` | SPA dashboard |
| Charts | `Recharts` | Feature importance, ROC, confusion matrix |
| Real-time stream | WebSocket (native) | Live flow and alert push |
| PDF export | `reportlab` | Server-side PDF generation |
| CSV export | `pandas` | DataFrame → CSV |
| JSON export | Python `json` | Structured output |
| Local storage | `SQLite` | Via `aiosqlite` (async) |
| ASGI server | `uvicorn` | FastAPI serving |

---

## Configuration (config.yaml)

```yaml
dashboard:
  host: "0.0.0.0"
  port: 8000
  reload: false                   # Set to true during development only

  report:
    max_flows_in_pdf: 500         # Limit flow rows in PDF export
    export_dir: "reports/"        # Directory for exported files

  websocket:
    max_connections: 10           # Maximum simultaneous WebSocket clients
    heartbeat_interval_sec: 30    # Ping/pong keepalive interval
```

---

## Deliverables

### Backend

| File | Description |
|---|---|
| `src/api/main.py` | FastAPI app entry point |
| `src/api/routes/capture.py` | Start / stop / pause live capture endpoints |
| `src/api/routes/upload.py` | PCAP file upload and processing endpoint |
| `src/api/routes/flows.py` | Flow record retrieval endpoints |
| `src/api/routes/alerts.py` | Alert retrieval endpoints |
| `src/api/routes/analytics.py` | ML metrics endpoint |
| `src/api/routes/reports.py` | PDF, CSV, JSON export endpoints |
| `src/api/websocket.py` | WebSocket stream handler |
| `src/api/__init__.py` | Module init and exports |

### Frontend

| File | Description |
|---|---|
| `frontend/src/components/SystemOverview.jsx` | System stats header |
| `frontend/src/components/TrafficSource.jsx` | Traffic mode selector and capture controls |
| `frontend/src/components/LiveTrafficMonitor.jsx` | Real-time flow table |
| `frontend/src/components/ThreatAlerts.jsx` | Filtered alert list |
| `frontend/src/components/FlowDetails.jsx` | Per-flow detail panel |
| `frontend/src/components/MLAnalytics.jsx` | Model performance charts |
| `frontend/src/components/Reports.jsx` | Export buttons and download links |
| `frontend/src/hooks/useWebSocket.js` | WebSocket subscription hook |
| `frontend/src/api/client.js` | REST API helper |
| `frontend/src/App.jsx` | Root component and layout |
| `frontend/package.json` | Node dependencies |
| `frontend/vite.config.js` | Vite build configuration |
