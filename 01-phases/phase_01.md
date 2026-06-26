# Phase 1 — Traffic Ingestion Layer

> **Position in Pipeline:** Entry point of the system
> **Privacy Constraint:** Packet payload is NEVER captured, stored, or inspected at any stage.

---

## Overview

Phase 1 is the entry point of the system. It accepts network traffic from two distinct sources — live network interfaces and uploaded PCAP files — and converts both into the same raw packet stream that feeds into Phase 2.

Both ingestion paths **merge into an identical processing pipeline** after capture, ensuring consistent behavior regardless of traffic source.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1 — TRAFFIC INGESTION LAYER                           │
│                                                              │
│  ┌──────────────────────────┐  ┌────────────────────────┐   │
│  │  Option A                │  │  Option B              │   │
│  │  Live Traffic Monitoring │  │  PCAP Upload           │   │
│  │                          │  │                        │   │
│  │  • Network Interface     │  │  • .pcap file          │   │
│  │  • Real-time capture     │  │  • .pcapng file        │   │
│  │  • Packet headers only   │  │  • Offline analysis    │   │
│  │  • Continuous stream     │  │  • Batch processing    │   │
│  └────────────┬─────────────┘  └──────────┬─────────────┘   │
│               │                            │                 │
│               └────────────┬───────────────┘                 │
│                            │                                 │
│                    MERGE — Same Pipeline                      │
│                            │                                 │
│                            ▼                                 │
│              [ Packet Filter: Headers Only ]                 │
│              [ Payload bytes discarded     ]                 │
│                            │                                 │
└────────────────────────────┼─────────────────────────────────┘
                             │
                   OUTPUT: Raw Packet Stream
```

---

## Option A — Live Traffic Monitoring

**Description:** Capture packets directly from a physical or virtual network interface in real-time.

| Property | Value |
|---|---|
| **Trigger** | User selects a network interface from the dashboard |
| **Capture Mode** | Continuous real-time packet sniffing |
| **Packet Scope** | Headers only (Ethernet, IP, TCP/UDP, TLS handshake) |
| **Payload Handling** | Discarded at capture layer — never stored |
| **Session Control** | Start / Stop / Pause controlled via dashboard |

**How it works:**
1. User selects a network interface from the dashboard (e.g., `eth0`, `Wi-Fi`).
2. `Scapy` opens a raw socket listener on the selected interface.
3. Each incoming packet is read at the header level.
4. Payload bytes are discarded immediately.
5. Packet objects (header only) are forwarded to the shared pipeline.

---

## Option B — PCAP Upload

**Description:** Upload previously captured `.pcap` or `.pcapng` files for offline forensic analysis.

| Property | Value |
|---|---|
| **Trigger** | User uploads a PCAP file through the dashboard |
| **File Formats** | `.pcap`, `.pcapng` |
| **Analysis Mode** | Offline / batch (entire file processed sequentially) |
| **Packet Scope** | Headers only (same as live capture) |
| **Payload Handling** | Payload bytes ignored during parsing |

**How it works:**
1. User uploads a PCAP file via the dashboard file upload form.
2. `Scapy` (or `pyshark` as fallback) reads packets from the file.
3. Only header fields are extracted for each packet.
4. Packet objects are forwarded into the same shared pipeline as live traffic.

---

## Merge Point — Shared Pipeline

After capture, both Option A and Option B produce identical packet objects containing:

```python
{
  "timestamp": float,       # Packet capture time (Unix epoch)
  "src_mac":   str,         # Ethernet source MAC
  "dst_mac":   str,         # Ethernet destination MAC
  "src_ip":    str,         # IP source address
  "dst_ip":    str,         # IP destination address
  "src_port":  int,         # TCP/UDP source port
  "dst_port":  int,         # TCP/UDP destination port
  "protocol":  str,         # "TCP" | "UDP" | "ICMP"
  "ip_flags":  int,         # IP header flags
  "ttl":       int,         # IP TTL
  "tcp_flags": str,         # e.g. "SYN", "ACK", "FIN", "RST", "PSH"
  "pkt_len":   int,         # Total packet length (header only)
  "tls_raw":   bytes | None # Raw TLS ClientHello bytes (if present)
  # payload:  NEVER STORED
}
```

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT A** | Network interface (live) — selected by user |
| **INPUT B** | .pcap / .pcapng file — uploaded by user |
| **OUTPUT** | Raw packet stream (headers only) |
| **Privacy** | Payload bytes discarded at capture |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Live capture engine | `Scapy` | Cross-platform, Windows-compatible |
| Capture driver (Windows) | `Npcap` | Required by Scapy on Windows |
| Capture driver (Linux) | `libpcap` | Required by Scapy on Linux |
| PCAP file reader | `Scapy` | Primary reader |
| PCAP fallback reader | `pyshark` | Uses Wireshark dissectors |
| Capture filter | BPF filter (Scapy) | Limit to header bytes only |

---

## Module: `src/ingestion/live_capture.py`

**Responsibilities:**
- List available network interfaces
- Open a raw socket listener on the selected interface
- Stream packets as header-only objects
- Support graceful start / stop / pause

**Key functions:**
```python
def list_interfaces() -> list[str]
    # Returns available network interfaces

def start_capture(interface: str, callback: Callable) -> None
    # Begins live packet capture; calls callback per packet

def stop_capture() -> None
    # Gracefully stops capture session
```

---

## Module: `src/ingestion/pcap_reader.py`

**Responsibilities:**
- Accept a PCAP or PCAPNG file path
- Read and iterate over all packets
- Yield header-only packet objects (same format as live capture)

**Key functions:**
```python
def read_pcap(file_path: str) -> Generator[dict, None, None]
    # Yields one packet dict per packet in the PCAP file
```

---

## Configuration (config.yaml)

```yaml
ingestion:
  capture_filter: ""          # BPF filter string (e.g., "tcp or udp")
  buffer_size: 65536          # Packet capture buffer size in bytes
  pcap_max_size_mb: 500       # Maximum PCAP upload size in MB
  store_payload: false        # Must always be false — privacy constraint
```

---

## Deliverables

| File | Description |
|---|---|
| `src/ingestion/live_capture.py` | Live network interface capture module |
| `src/ingestion/pcap_reader.py` | Offline PCAP file reader module |
| `src/ingestion/__init__.py` | Module init and exports |

---

## Privacy Statement

> At no point in Phase 1 does the system access, read, store, or forward packet payload bytes.
> The capture filter discards payload before any packet object is created.
> This is the foundational privacy guarantee of the system.
