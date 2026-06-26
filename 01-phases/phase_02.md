# Phase 2 — Packet Parsing & Flow Generation

> **Position in Pipeline:** Receives raw packet stream from Phase 1 → Outputs bidirectional flow records to Phase 3
> **Purpose:** Parse packet headers and build bidirectional network flows using the 5-tuple key.

---

## Overview

Phase 2 receives individual raw packets (headers only) from Phase 1 and converts them into **bidirectional network flows**. A flow is a group of packets sharing the same network conversation, identified by the 5-tuple: source IP, destination IP, source port, destination port, and protocol.

This phase handles:
- **Header parsing** — reading fields from each protocol layer
- **Flow aggregation** — grouping packets into conversations
- **Timeout management** — closing flows that have gone idle or expired
- **Session reconstruction** — tracking bidirectional packet exchanges

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2 — PACKET PARSING & FLOW GENERATION                  │
│                                                              │
│  INPUT: Raw Packet Stream (from Phase 1)                     │
│                                                              │
│  Step 1 — Header Parsing                                     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────┐  │
│  │   Ethernet    │ │      IP       │ │    TCP / UDP      │  │
│  │    Header     │ │    Header     │ │     Header        │  │
│  │               │ │               │ │                   │  │
│  │ src_mac       │ │ src_ip        │ │ src_port          │  │
│  │ dst_mac       │ │ dst_ip        │ │ dst_port          │  │
│  │ ethertype     │ │ ttl           │ │ flags             │  │
│  │               │ │ protocol      │ │ seq / ack num     │  │
│  └───────────────┘ └───────────────┘ └───────────────────┘  │
│                    ┌─────────────────────────────────────┐   │
│                    │         TLS Handshake Header        │   │
│                    │                                     │   │
│                    │  handshake_type | version           │   │
│                    │  cipher_suites  | extensions        │   │
│                    │  sni            | alpn              │   │
│                    │  ja3_raw_fields                     │   │
│                    └─────────────────────────────────────┘   │
│                                                              │
│  Step 2 — Flow Builder                                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Flow Key: (src_ip, dst_ip, src_port, dst_port, proto)│  │
│  │                                                       │  │
│  │  Active Flow Table (in-memory dict)                   │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │  │
│  │  │ Flow A  │ │ Flow B  │ │ Flow C  │ │ Flow D  │    │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘    │  │
│  │                                                       │  │
│  │  Timeout Manager:                                     │  │
│  │    Active timeout : 120 seconds                       │  │
│  │    Idle timeout   : 30 seconds                        │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  OUTPUT: Completed Flow Records                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Header Parsing

### Ethernet Header

| Field | Description | Used For |
|---|---|---|
| `src_mac` | Source MAC address | Device identification |
| `dst_mac` | Destination MAC address | Device identification |
| `ethertype` | Protocol type (0x0800 = IPv4) | Protocol routing |

### IP Header

| Field | Description | Used For |
|---|---|---|
| `src_ip` | Source IP address | Flow key (5-tuple) |
| `dst_ip` | Destination IP address | Flow key (5-tuple) |
| `ttl` | Time to live | Network topology hints |
| `protocol` | Transport protocol (6=TCP, 17=UDP) | Flow key (5-tuple) |
| `ip_flags` | Fragmentation flags | Anomaly signal |
| `pkt_len` | Total IP packet length | Packet size tracking |

### TCP Header

| Field | Description | Used For |
|---|---|---|
| `src_port` | Source port number | Flow key (5-tuple) |
| `dst_port` | Destination port number | Flow key (5-tuple) |
| `tcp_flags` | Control bits: SYN/ACK/FIN/RST/PSH/URG | TCP feature extraction |
| `seq_num` | Sequence number | Session tracking |
| `ack_num` | Acknowledgment number | Session tracking |
| `window_size` | TCP window size | Flow behavior signal |

### UDP Header

| Field | Description | Used For |
|---|---|---|
| `src_port` | Source port | Flow key |
| `dst_port` | Destination port | Flow key |
| `length` | UDP payload length | Packet sizing |

### TLS Handshake Header (ClientHello only)

Parsed **only when** a TCP packet contains a TLS ClientHello message (first byte = 0x16, handshake type = 0x01).

| Field | Description | Used For |
|---|---|---|
| `tls_version` | Offered TLS version | Feature extraction |
| `cipher_suites` | List of proposed cipher suites | JA3 computation |
| `extensions` | TLS extension IDs | JA3 computation |
| `sni` | Server Name Indication | Domain identification |
| `alpn` | Application-layer protocol name | Protocol identification |
| `elliptic_curves` | Supported elliptic curves | JA3 computation |
| `ec_point_formats` | EC point formats | JA3 computation |

> **Note:** Only ClientHello and ServerHello headers are parsed. The TLS application data (encrypted content) is never read.

---

## Step 2 — Bidirectional Flow Builder

### What is a Flow?

A **flow** is a group of packets that share the same 5-tuple throughout a network session:

```
Flow Key = (Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

The flow builder normalizes the key so that packets in both directions (forward and backward) belong to the same flow:

```
Forward:  (192.168.1.10, 8.8.8.8, 54321, 443, TCP)
Backward: (8.8.8.8, 192.168.1.10, 443, 54321, TCP)

Both → Same Flow Key (canonical form: smaller IP/port first)
```

### Active Flow Table

An **in-memory dictionary** maps each flow key to a `FlowRecord` object:

```python
flow_table: dict[tuple, FlowRecord] = {}

class FlowRecord:
    flow_id:       str             # UUID
    src_ip:        str
    dst_ip:        str
    src_port:      int
    dst_port:      int
    protocol:      str
    start_time:    float           # Unix timestamp of first packet
    last_seen:     float           # Unix timestamp of last packet
    fwd_packets:   list[PacketInfo]  # Packets src → dst
    bwd_packets:   list[PacketInfo]  # Packets dst → src
    tls_data:      TLSInfo | None  # TLS handshake metadata
    is_complete:   bool
```

### Flow Lifecycle

```
Packet arrives
      │
      ▼
Look up flow_key in flow_table
      │
      ├─── Existing flow found
      │         └─── Add packet to fwd_packets or bwd_packets
      │               Update last_seen timestamp
      │
      └─── No existing flow
                └─── Create new FlowRecord
                      Add first packet
                      Store in flow_table

On timeout check (every 5 seconds):
      │
      ├─── Active timeout: now - start_time > 120s
      │         └─── Finalize flow → output to Phase 3
      │
      └─── Idle timeout: now - last_seen > 30s
                └─── Finalize flow → output to Phase 3

On FIN/RST packet:
      └─── Finalize flow immediately → output to Phase 3
```

### Flow Timeout Rules

| Timeout Type | Duration | Trigger Condition |
|---|---|---|
| **Active timeout** | 120 seconds | Flow age exceeds 120s from first packet |
| **Idle timeout** | 30 seconds | No packets seen for 30s |
| **TCP FIN** | Immediate | FIN flag detected |
| **TCP RST** | Immediate | RST flag detected |

---

## Flow Record Output Format

Each completed flow produces a structured record:

```python
{
  "flow_id":          str,      # UUID
  "src_ip":           str,
  "dst_ip":           str,
  "src_port":         int,
  "dst_port":         int,
  "protocol":         str,      # "TCP" | "UDP"
  "start_time":       float,    # Unix timestamp
  "end_time":         float,    # Unix timestamp
  "duration":         float,    # seconds
  "fwd_packets": [
    {
      "timestamp":  float,
      "pkt_len":    int,
      "tcp_flags":  str | None
    }, ...
  ],
  "bwd_packets": [...],
  "tls": {
    "version":       str | None,   # "TLSv1.2", "TLSv1.3", etc.
    "cipher_suites": list[int],
    "extensions":    list[int],
    "sni":           str | None,
    "alpn":          list[str],
    "ec_curves":     list[int],
    "ec_formats":    list[int]
  } | None
}
```

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | Raw packet stream (from Phase 1) |
| **OUTPUT** | Completed bidirectional flow records |
| **Privacy** | No payload bytes stored in flow records |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| Packet parsing | `Scapy` | Header field access |
| Fast header dissection | `dpkt` | Binary TLS parsing |
| TLS header parsing | Custom Python + `dpkt` | ClientHello field extraction |
| Flow table management | Python `dict` + `dataclass` | In-memory, no external dependency |
| Timeout management | Python `threading.Timer` or async scheduler | Background expiry checking |

---

## Modules

### `src/parsing/packet_parser.py`

```python
def parse_packet(pkt: scapy.Packet) -> dict | None
    # Parses Ethernet, IP, TCP/UDP, and TLS headers from a Scapy packet object
    # Returns a structured header dict, or None if packet is malformed

def parse_tls_clienthello(raw_bytes: bytes) -> dict | None
    # Parses TLS ClientHello from raw TCP payload bytes
    # Returns TLS fields dict or None if not a TLS ClientHello
```

### `src/parsing/flow_builder.py`

```python
class FlowBuilder:
    def add_packet(self, pkt_dict: dict) -> FlowRecord | None
        # Adds packet to the appropriate flow
        # Returns a completed FlowRecord if a flow was finalized, else None

    def get_active_flows(self) -> list[FlowRecord]
        # Returns all currently active (incomplete) flows

    def flush_expired_flows(self) -> list[FlowRecord]
        # Checks timeouts and returns all expired flows
```

---

## Configuration (config.yaml)

```yaml
flow_builder:
  active_timeout_sec: 120     # Close flows older than this
  idle_timeout_sec: 30        # Close flows idle longer than this
  max_active_flows: 100000    # Safety limit on simultaneous active flows
  check_interval_sec: 5       # How often to check for expired flows
```

---

## Deliverables

| File | Description |
|---|---|
| `src/parsing/packet_parser.py` | Ethernet/IP/TCP/UDP/TLS header parser |
| `src/parsing/flow_builder.py` | Bidirectional flow tracker with timeout management |
| `src/parsing/__init__.py` | Module init and exports |
