# Phase 1: Data Collection & Traffic Capture

> **Duration:** 2 weeks  
> **Status:** Not started  
> **Depends on:** None  
> **Feeds into:** Phase 2 (Feature Engineering)

---

## 1. Objective

Build the data ingestion foundation of the detection system. Capture bidirectional network flow records from live network interfaces and offline PCAP files — extracting only protocol headers and handshake metadata. **No payload content is ever stored or inspected.**

This phase produces the raw flow records that every downstream component (feature extraction, ML, alerting) consumes.

---

## 2. Core Concepts

### 2.1 What Is a Flow?

A **bidirectional flow** is the complete conversation between two endpoints, identified by the 5-tuple:

```
(src_ip, dst_ip, src_port, dst_port, protocol)
```

All packets matching this 5-tuple (in either direction) are grouped into a single flow record. Key invariants:
- We treat `(A→B)` and `(B→A)` as **the same flow**, canonicalizing by sorting the tuple.
- Each flow has an **Active Timeout** (120s) — the maximum duration before the flow is forcibly exported, even if traffic continues.
- Each flow has an **Idle Timeout** (30s) — if no packets arrive within 30s, the flow is considered finished and exported.

### 2.2 What We Capture (and What We Don't)

| Captured | Not Captured |
|---|---|
| IP header fields (src/dst addresses, TTL, flags) | TLS payload (encrypted application data) |
| TCP/UDP header fields (ports, flags, sequence numbers) | HTTP body / request content |
| TLS ClientHello and ServerHello metadata | DNS answer payloads |
| Packet arrival timestamps | Any content above the transport layer |
| Packet sizes (total bytes per packet) | |
| DNS query names (header-level, not answers) | |

This is the **privacy guarantee** of the entire system. It is enforced at the capture layer — NFStream and Scapy both operate at the packet header level by default.

### 2.3 Why NFStream as Primary

NFStream is not just a packet sniffer. It implements a **stateful flow table** that:
- Reconstructs bidirectional flows automatically.
- Computes aggregate statistics (mean/std/min/max of packet sizes and IATs) per flow natively.
- Performs application-layer dissection using nDPI to extract TLS metadata `(SNI, JA3, JA3S, cipher suites, TLS version)` without decrypting traffic.
- Supports both live capture (Linux, requires `CAP_NET_RAW`) and offline PCAP as input sources.

---

## 3. Platform & Compatibility

> **⚠️ Critical Design Decision:** This system's capture layer is **Linux-first.**

| Component | Linux | Windows | macOS |
|---|---|---|---|
| NFStream (primary) | ✅ Full support | ⚠️ Experimental / breaks often | ✅ Supported |
| Scapy (fallback) | ✅ Full support | ✅ Supported (with Npcap) | ✅ Supported |
| AF_PACKET (high-perf) | ✅ Native | ❌ Not available | ❌ Not available |
| DPDK (10Gbps+) | ✅ Supported | ❌ Not available | ❌ Not available |
| libpcap | ✅ Native | ✅ via WinPcap/Npcap | ✅ Native |

**Decision:** For Windows sensors (common in enterprise deployments), the capture layer will use `Scapy + Npcap`. The Scapy backend produces a less-rich feature set (no native JA3 extraction, no bidirectional accounting). For production deployments requiring full feature fidelity, sensors must run Linux. This limitation is explicitly documented and must be communicated to operators.

**Actionable:** Add a `--backend` flag to both capture modules with options `nfstream | scapy | auto`. The `auto` mode detects the OS and selects the appropriate backend.

---

## 4. Input Modes

### 4.1 Live NIC Capture (`live_capture.py`)

Listens on a specified network interface and exports flows as they complete (when timeouts fire).

**Requirements:**
- Linux: `sudo` or `CAP_NET_RAW` capability.
- Windows: Npcap must be installed; run as Administrator.

**Output targets:**
- **Redis Streams:** For real-time detection pipeline (production mode).
- **Parquet file (buffered):** For logging flows to disk during capture sessions.

**Key parameters:**
```
--interface eth0          # Network interface to listen on
--active-timeout 120      # Force-export flows after 120s
--idle-timeout 30         # Export idle flows after 30s
--output-mode stream      # 'stream' (Redis) or 'file' (Parquet)
--allowlist-cidr ...      # Skip feature extraction on known-safe CIDRs
```

> **Allow-listing at the Capture Layer:** Known-safe traffic (e.g., monitoring systems, backup agents, trusted internal servers) should be filtered out **here**, not after ML inference. Running inference on Amazon S3 backup traffic will generate false positives and waste CPU. Allowlisted flows are logged at INFO level but not processed further.

### 4.2 Offline PCAP Analysis (`pcap_reader.py`)

Reads one or more PCAP/PCAPNG files and exports all reconstructed flows.

**Primary use cases:**
- Processing labeled training datasets (CICIDS2017, CTU-13, etc.).
- Post-incident forensic analysis.
- CI/CD integration testing (sample PCAPs in `tests/fixtures/`).

**Key parameters:**
```
--input path/to/file.pcap      # Single PCAP or directory of PCAPs
--output data/processed/       # Destination directory for Parquet output
--label BENIGN                 # Optional ground-truth label for training data
--backend nfstream             # Explicit backend selection
```

---

## 5. Flow Record Schema

The output of Phase 1 is a standardized flow record. Every field below is available for Phase 2 feature extraction.

```python
{
    # --- Identity ---
    "src_ip":          str,    # Source IP address
    "dst_ip":          str,    # Destination IP address
    "src_port":        int,    # Source port
    "dst_port":        int,    # Destination port
    "protocol":        int,    # IP protocol number (6=TCP, 17=UDP)
    "first_seen_ms":   int,    # Flow start timestamp (epoch ms)
    "last_seen_ms":    int,    # Flow end timestamp (epoch ms)
    "capture_ts":      str,    # ISO8601 export timestamp

    # --- Duration & Volumes ---
    "flow_duration":   float,  # seconds
    "total_fwd_packets": int,
    "total_bwd_packets": int,
    "total_fwd_bytes": int,
    "total_bwd_bytes": int,

    # --- Packet Size Statistics ---
    "fwd_pkt_len_mean": float,
    "fwd_pkt_len_std":  float,
    "fwd_pkt_len_min":  float,
    "fwd_pkt_len_max":  float,
    "bwd_pkt_len_mean": float,
    "bwd_pkt_len_std":  float,
    "bwd_pkt_len_min":  float,
    "bwd_pkt_len_max":  float,

    # --- IAT Statistics ---
    "flow_iat_mean": float,    # Bidirectional inter-arrival time (ms)
    "flow_iat_std":  float,
    "flow_iat_min":  float,
    "flow_iat_max":  float,
    "fwd_iat_mean":  float,
    "fwd_iat_std":   float,
    "fwd_iat_min":   float,
    "fwd_iat_max":   float,
    "bwd_iat_mean":  float,
    "bwd_iat_std":   float,
    "bwd_iat_min":   float,
    "bwd_iat_max":   float,

    # --- TCP Flags ---
    "fwd_syn_count": int,
    "bwd_syn_count": int,
    "fwd_fin_count": int,
    "bwd_fin_count": int,
    "fwd_rst_count": int,
    "bwd_rst_count": int,
    "fwd_psh_count": int,
    "bwd_psh_count": int,
    "fwd_ack_count": int,
    "fwd_urg_count": int,

    # --- TLS / Application Metadata (NFStream only) ---
    "requested_server_name": str | None,   # SNI field from ClientHello
    "client_fingerprint":    str | None,   # JA3 hash
    "server_fingerprint":    str | None,   # JA3S hash
    "application_name":      str | None,   # nDPI classification (e.g. "TLS.Google")
    "application_category":  str | None,

    # --- Optional: Ground Truth (training mode only) ---
    "label":        str | None,   # e.g. "BENIGN", "DDoS", "C2"
    "source_file":  str | None,   # Name of source PCAP file
}
```

---

## 6. Key Design Decisions

### 6.1 Subflow Definition

The plan references subflow-level features (`subflow_fwd_packets`, `subflow_bwd_packets`). **A subflow is defined as follows:**

> A subflow is a contiguous sequence of packets within a parent flow separated by an idle gap exceeding a configurable threshold (default: **1 second**).

Example: A C2 beacon sending 3 packets every 60 seconds produces approximately 60 subflows within a 120-second active timeout window. The parent flow has `subflow_count = 60`, `subflow_avg_packets = 3`. This is a strong beaconing signal.

NFStream computes SPLT (Sub-Packet-Level Timing) for the first N packets, which we use to bootstrap subflow detection.

### 6.2 Allow-listing at the Capture Layer

The allow-list is checked **before feature extraction and before any inference**. It is not a post-hoc suppression mechanism. This matters because:
- It removes guaranteed false positives before they inflate FP metrics.
- It avoids burning CPU on ML inference for monitoring endpoints, CI/CD systems, and known-safe internal services.

Allow-list entries supported:
- CIDR ranges: `192.168.1.0/24`
- Domain patterns: `*.windows.com` (matched against SNI)
- JA3 hashes: for known-safe TLS clients (e.g., Chrome, Firefox stable)

### 6.3 JARM — Active vs. Passive (Critical Distinction)

> **JARM is NOT a passive fingerprint. It requires active network probing and cannot be extracted from captured traffic.**

| | JA3 | JA3S | JARM |
|---|---|---|---|
| **Source** | TLS ClientHello | TLS ServerHello | Active probe: 10 crafted ClientHellos sent to server |
| **Computed by** | Passive capture | Passive capture | Active module (analyst-triggered) |
| **Direction** | Client fingerprint | Server fingerprint | Server fingerprint |
| **Availability** | Every TLS flow | Every TLS flow that completes | On-demand investigation only |

**Architecture decision:** JARM is moved entirely out of the passive capture pipeline. It lives in `src/threat_intel/jarm_probe.py` — an **Investigation Module** that an analyst can trigger on a suspicious destination IP. It is never computed automatically during capture. This prevents confusion during implementation.

---

## 7. Data Validation Checkpoint

Before any flow record from this phase is forwarded to training pipelines, it passes through a validation gate:

```
Validate:
  ✓ flow_duration > 0
  ✓ total_fwd_packets + total_bwd_packets >= 2
  ✓ No NaN/null in required fields
  ✓ src_ip and dst_ip are valid addresses
  ✓ Not in allowlist (already filtered at capture)
```

Invalid records are logged to `data/processed/rejected_flows.parquet` with a `rejection_reason` field for audit.

---

## 8. Deliverables

| File | Description |
|---|---|
| `src/capture/__init__.py` | Package init |
| `src/capture/live_capture.py` | Live NIC capture (NFStream primary, Scapy fallback) |
| `src/capture/pcap_reader.py` | Offline PCAP analysis (NFStream primary, Scapy fallback) |
| `src/capture/flow_validator.py` | Flow record validation and rejection logic |
| `src/capture/allowlist.py` | CIDR/domain/JA3 allow-list engine |
| `data/raw/` | Directory for raw PCAP files (git-ignored) |
| `data/processed/` | Output directory for Parquet flow records |

---

## 9. Acceptance Criteria

- [ ] `live_capture.py` captures and exports flows successfully on Linux (`NFStream`).
- [ ] `live_capture.py` runs on Windows using `Scapy + Npcap` fallback with a documented feature limitation note.
- [ ] `pcap_reader.py` processes a CICIDS2017 PCAP and exports a valid Parquet file.
- [ ] The Parquet schema matches the flow record schema exactly (validated by a pytest fixture).
- [ ] Allow-listed CIDRs produce zero flow records in the output.
- [ ] JARM is confirmed absent from this module (confirmed by grep test in CI).
- [ ] Rejected flows are written to `rejected_flows.parquet` with `rejection_reason`.
- [ ] CLI `--help` is documented and tested for both scripts.
