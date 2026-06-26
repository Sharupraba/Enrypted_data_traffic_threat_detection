# Phase 3 — Metadata & Feature Extraction

> **Position in Pipeline:** Receives flow records from Phase 2 → Outputs structured metadata dataset to Phase 4
> **Privacy Constraint:** Only metadata is extracted. Encrypted payload is NEVER inspected, decoded, or stored.

---

## Overview

Phase 3 extracts **structured metadata** from each bidirectional flow record. All information is derived exclusively from:
- Packet headers (IP, TCP/UDP)
- Packet-level statistics (sizes, counts, timestamps)
- TLS handshake fields (ClientHello / ServerHello only)
- DNS query fields (query name, response code)

> 🔒 **Zero Payload Rule:** This phase never accesses, reads, or processes encrypted payload bytes. All features are computed from headers and packet-level observations.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3 — METADATA & FEATURE EXTRACTION                         │
│                                                                  │
│  INPUT: Bidirectional Flow Records (from Phase 2)                │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Flow Feature │  │  TCP Feature │  │  Timing Feature      │   │
│  │ Extractor    │  │  Extractor   │  │  Extractor           │   │
│  │              │  │              │  │                      │   │
│  │ flow_features│  │ tcp_features │  │ timing_features.py   │   │
│  │   .py        │  │   .py        │  │                      │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐  │
│  │  TLS Feature Extractor   │  │  DNS Feature Extractor       │  │
│  │                          │  │                              │  │
│  │  tls_features.py         │  │  dns_features.py             │  │
│  └──────────────────────────┘  └──────────────────────────────┘  │
│                                                                  │
│                         ┌────────────────┐                       │
│                         │  extractor.py  │                       │
│                         │  (Orchestrator)│                       │
│                         └────────────────┘                       │
│                                                                  │
│  OUTPUT: Structured Metadata Dataset (one row per flow)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Feature Groups

### Group 1 — Flow Features

> Source: `src/extraction/flow_features.py`

Computed from packet counts, byte totals, and timestamps across both directions.

| Feature | Type | Description |
|---|---|---|
| `flow_duration` | float | Duration in seconds (`end_time - start_time`) |
| `total_fwd_packets` | int | Packets sent src → dst |
| `total_bwd_packets` | int | Packets sent dst → src |
| `total_packets` | int | Total packets in flow |
| `bytes_sent` | int | Total bytes src → dst |
| `bytes_received` | int | Total bytes dst → src |
| `total_bytes` | int | Total bytes in flow |
| `avg_fwd_packet_size` | float | Mean packet size forward direction |
| `avg_bwd_packet_size` | float | Mean packet size backward direction |
| `avg_packet_size` | float | Mean packet size both directions |
| `fwd_pkt_size_std` | float | Std deviation of forward packet sizes |
| `bwd_pkt_size_std` | float | Std deviation of backward packet sizes |
| `packets_per_sec` | float | `total_packets / flow_duration` |
| `bytes_per_sec` | float | `total_bytes / flow_duration` |
| `fwd_bytes_per_sec` | float | Forward throughput rate |
| `bwd_bytes_per_sec` | float | Backward throughput rate |

---

### Group 2 — TCP Features

> Source: `src/extraction/tcp_features.py`

Computed from TCP flag fields in packet headers.

| Feature | Type | Description |
|---|---|---|
| `syn_count` | int | Number of SYN packets |
| `ack_count` | int | Number of ACK packets |
| `fin_count` | int | Number of FIN packets |
| `rst_count` | int | Number of RST packets |
| `psh_count` | int | Number of PSH packets |
| `urg_count` | int | Number of URG packets |
| `syn_rate` | float | `syn_count / total_packets` |
| `rst_rate` | float | `rst_count / total_packets` |
| `psh_rate` | float | `psh_count / total_packets` |
| `fwd_syn_count` | int | SYN packets forward direction only |
| `bwd_syn_count` | int | SYN packets backward direction only |
| `fin_rst_ratio` | float | `(fin_count + rst_count) / total_packets` |

---

### Group 3 — Timing Features

> Source: `src/extraction/timing_features.py`

Computed from the inter-arrival time (IAT) between consecutive packets.

**Inter-Arrival Time (IAT):** The time difference between consecutive packets arriving in the same flow.

| Feature | Type | Description |
|---|---|---|
| `iat_mean` | float | Mean IAT across all packets (ms) |
| `iat_std` | float | Standard deviation of IAT |
| `iat_min` | float | Minimum IAT |
| `iat_max` | float | Maximum IAT |
| `fwd_iat_mean` | float | Mean IAT in forward direction |
| `fwd_iat_std` | float | Std deviation of forward IAT |
| `bwd_iat_mean` | float | Mean IAT in backward direction |
| `bwd_iat_std` | float | Std deviation of backward IAT |
| `burst_count` | int | Number of burst events detected |
| `burst_avg_size` | float | Average packets per burst |
| `active_time_mean` | float | Mean duration of active periods |
| `idle_time_mean` | float | Mean duration of idle periods |

**Burst Detection Rule:**
A "burst" is defined as a group of packets with IAT < 10ms, separated by idle periods of IAT > 100ms.

---

### Group 4 — TLS Metadata

> Source: `src/extraction/tls_features.py`

Extracted from TLS ClientHello and ServerHello header fields only. No encrypted content is accessed.

| Feature | Type | Description |
|---|---|---|
| `tls_version` | str | Negotiated TLS version (e.g., "TLSv1.3") |
| `tls_version_risk` | int | Risk score: 2=TLS<1.2, 1=TLS1.2, 0=TLS1.3 |
| `cipher_suite` | str | Negotiated cipher suite name |
| `cipher_is_weak` | bool | True if cipher suite is known-weak |
| `ja3_hash` | str | MD5 fingerprint of TLS ClientHello fields |
| `ja3s_hash` | str | MD5 fingerprint of TLS ServerHello fields |
| `sni` | str | Server Name Indication (domain name) |
| `sni_is_ip` | bool | True if SNI is an IP address (suspicious) |
| `has_sni` | bool | True if SNI extension is present |
| `alpn` | str | Application-layer protocol (e.g., "h2", "http/1.1") |
| `alpn_is_suspicious` | bool | True if ALPN is unusual for the destination port |
| `tls_extension_count` | int | Number of extensions in ClientHello |
| `cert_self_signed` | bool | True if server cert is self-signed |
| `cert_expired` | bool | True if server cert is past expiry |
| `cert_days_to_expiry` | int | Days until certificate expiry |
| `cert_domain_mismatch` | bool | True if SNI ≠ certificate CN/SAN |
| `cert_is_short_lived` | bool | True if cert valid < 30 days |

**JA3 Hash Computation:**
```
JA3 = MD5(TLSVersion + CipherSuites + Extensions + EllipticCurves + ECPointFormats)
```
The JA3 hash uniquely identifies a TLS client configuration — useful for detecting malware TLS patterns without reading encrypted content.

---

### Group 5 — DNS Features *(if available)*

> Source: `src/extraction/dns_features.py`

Extracted only from unencrypted DNS query/response headers (port 53, UDP). DNS over HTTPS (DoH) flows have no DNS features.

| Feature | Type | Description |
|---|---|---|
| `dns_domain` | str | Queried domain name |
| `dns_query_frequency` | float | Number of queries per second for this host |
| `domain_entropy` | float | Shannon entropy of domain label characters |
| `nxdomain_rate` | float | Fraction of DNS responses with NXDOMAIN code |
| `dns_response_count` | int | Number of DNS responses observed |
| `subdomain_level` | int | Number of subdomains in the domain (depth) |

**Domain Entropy:**
High entropy in domain labels (> 3.5 bits/char) is a signal for Domain Generation Algorithm (DGA) malware.

```
entropy = -sum(p * log2(p)) for each character frequency p in domain
```

---

## Extractor Orchestrator

> Source: `src/extraction/extractor.py`

Orchestrates all five extractors and assembles the complete feature row for each flow:

```python
def extract_features(flow: FlowRecord) -> dict:
    """
    Takes a completed FlowRecord from Phase 2.
    Runs all five extractors.
    Returns a single flat dict with all metadata features.
    Returns None if the flow has insufficient packets to extract features.
    """
    features = {}
    features.update(extract_flow_features(flow))
    features.update(extract_tcp_features(flow))
    features.update(extract_timing_features(flow))
    features.update(extract_tls_features(flow))
    features.update(extract_dns_features(flow))
    return features
```

---

## Output Format

Each flow produces one metadata row:

```python
{
  # Identifiers
  "flow_id":               str,
  "src_ip":                str,
  "dst_ip":                str,
  "src_port":              int,
  "dst_port":              int,
  "protocol":              str,
  "timestamp":             float,

  # Flow Features
  "flow_duration":         float,
  "total_fwd_packets":     int,
  "total_bwd_packets":     int,
  "bytes_sent":            int,
  "bytes_received":        int,
  "avg_packet_size":       float,
  "packets_per_sec":       float,
  "bytes_per_sec":         float,

  # TCP Features
  "syn_count":             int,
  "ack_count":             int,
  "fin_count":             int,
  "rst_count":             int,
  "psh_count":             int,

  # Timing Features
  "iat_mean":              float,
  "iat_std":               float,
  "iat_min":               float,
  "iat_max":               float,
  "burst_count":           int,

  # TLS Metadata
  "tls_version":           str | None,
  "cipher_suite":          str | None,
  "ja3_hash":              str | None,
  "ja3s_hash":             str | None,
  "sni":                   str | None,
  "alpn":                  str | None,
  "cert_self_signed":      bool | None,
  "cert_expired":          bool | None,
  "cert_days_to_expiry":   int | None,

  # DNS Features
  "dns_domain":            str | None,
  "domain_entropy":        float | None,
  "nxdomain_rate":         float | None,
  "dns_query_frequency":   float | None,
}
```

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | Completed bidirectional flow records (from Phase 2) |
| **OUTPUT** | Structured metadata dataset (one row per flow, ~50 features) |
| **Privacy** | No payload bytes in output. All features are header-derived. |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| JA3/JA3S computation | `pyja3` | MD5 of TLS hello fields |
| TLS parsing | `dpkt`, `cryptography` | ClientHello / ServerHello only |
| Statistical computation | `numpy`, `scipy.stats` | IAT stats, entropy |
| Data assembly | `pandas` | Assembles feature rows into DataFrame |
| DNS parsing | `Scapy` DNS layer | Port 53 UDP/TCP packets |

---

## Deliverables

| File | Description |
|---|---|
| `src/extraction/flow_features.py` | Flow-level statistics extractor |
| `src/extraction/tcp_features.py` | TCP flag counter and rate calculator |
| `src/extraction/timing_features.py` | IAT statistics and burst detection |
| `src/extraction/tls_features.py` | TLS metadata extractor (JA3, SNI, cert, cipher) |
| `src/extraction/dns_features.py` | DNS entropy and NXDOMAIN extractor |
| `src/extraction/extractor.py` | Orchestrator — combines all extractors |
| `src/extraction/__init__.py` | Module init and exports |
