# Phase 6 — Threat Intelligence Enrichment

> **Position in Pipeline:** Receives ML prediction from Phase 5 → Outputs enriched threat context to Phase 7
> **Role:** Enrichment layer only. This phase does NOT perform threat detection.

---

## Overview

Phase 6 runs **only on flows that the ML model has already classified as threats** in Phase 5. Its sole responsibility is to enrich those detections with external reputation data and contextual signals so that the Risk Scoring Engine (Phase 7) can produce a more accurate final score.

> ⚠️ **Critical Design Rule:** This phase does NOT generate new threat detections or alerts. It receives a completed ML prediction and adds contextual metadata to it. Detection authority belongs exclusively to Phase 5.

---

## What This Phase Does

| Function | Description |
|---|---|
| **IP Reputation** | Check source/destination IPs against external threat intelligence databases |
| **Domain Reputation** | Evaluate the SNI domain name for known-malicious classifications |
| **JA3 Fingerprint Matching** | Match the flow's JA3 hash against known-malicious TLS fingerprint databases |
| **Certificate Reputation** | Assess certificate trustworthiness (self-signed, expired, domain mismatch) |

---

## Enrichment Sources

### IP Reputation

| Source | API | Output |
|---|---|---|
| **AbuseIPDB** | `GET /api/v2/check?ipAddress={ip}` | Abuse confidence score (0–100) |
| **VirusTotal** | `GET /api/v3/ip_addresses/{ip}` | Malicious / Suspicious / Harmless vote counts |

Combined into a single `ip_reputation_score` (0–100):
```
ip_reputation_score = max(abuseipdb_score, virustotal_malicious_ratio × 100)
```

### Domain Reputation

| Source | API | Output |
|---|---|---|
| **VirusTotal** | `GET /api/v3/domains/{domain}` | Malicious / Suspicious / Harmless vote counts |

Applied to the `sni` field extracted from TLS ClientHello headers in Phase 3.

### JA3 Fingerprint Matching

JA3 hashes computed in Phase 3 are matched against community-maintained databases of known-malicious TLS client fingerprints.

| Source | Method | Output |
|---|---|---|
| Salesforce JA3 database | Local lookup (JSON file bundled with system) | `ja3_match: true/false`, `ja3_threat_label` |
| Community JA3 feeds | Periodically downloaded JSON | `ja3_match_score` (0–100) |

> **Note:** JA3 matching uses pre-downloaded fingerprint lists only. No active TLS probing is performed.

### Certificate Reputation

Certificate assessment is based on metadata extracted during Phase 2 (TLS handshake) and Phase 3 (feature extraction). No active certificate fetching is required.

| Check | Field | Risk Indicator |
|---|---|---|
| Self-signed certificate | `cert_self_signed` | High risk — no CA chain |
| Expired certificate | `cert_expired` | Medium risk — certificate maintenance failure |
| Short-lived certificate | `cert_is_short_lived` | Medium risk — automated issuance (phishing pattern) |
| Domain mismatch | `cert_domain_mismatch` | High risk — SNI ≠ certificate CN/SAN |

Certificate risk is aggregated into a `cert_risk_score` (0–100).

---

## Input / Output

### Input (from Phase 5)

```python
{
  "flow_id":        str,      # UUID of the analyzed flow
  "classification": str,      # "THREAT" — only threats are enriched
  "confidence":     float,    # ML confidence 0.0–1.0
  "src_ip":         str,
  "dst_ip":         str,
  "sni":            str | None,
  "ja3_hash":       str | None,
  "cert_self_signed":     bool | None,
  "cert_expired":         bool | None,
  "cert_is_short_lived":  bool | None,
  "cert_domain_mismatch": bool | None
}
```

### Output (to Phase 7)

```python
{
  # All input fields passed through, plus:
  "ip_reputation_score":    int,       # 0–100 (100 = confirmed malicious)
  "domain_reputation_score": int,      # 0–100 (100 = confirmed malicious)
  "ja3_match":              bool,      # True if JA3 matches known-bad fingerprint
  "ja3_match_score":        int,       # 0–100
  "ja3_threat_label":       str | None, # e.g. "Cobalt Strike", "Emotet"
  "cert_risk_score":        int,       # 0–100
  "enrichment_available":   bool       # False if all APIs unavailable (graceful fallback)
}
```

---

## Caching

All external API responses are cached in-memory to avoid redundant lookups and reduce latency.

| Cache Key | TTL | Rationale |
|---|---|---|
| `ip:{ip_address}` | 1 hour | IP reputation changes slowly |
| `domain:{domain}` | 6 hours | Domain reputation is stable |
| `ja3:{hash}` | 24 hours | JA3 fingerprint database is static |

**Implementation:** Python `cachetools` TTLCache — no external database required.

```python
from cachetools import TTLCache

ip_cache     = TTLCache(maxsize=10000, ttl=3600)
domain_cache = TTLCache(maxsize=5000,  ttl=21600)
ja3_cache    = TTLCache(maxsize=50000, ttl=86400)
```

---

## Graceful Fallback

If external APIs are unavailable or API rate limits are reached:
- All reputation scores default to `0` (neutral — not penalized)
- `enrichment_available` is set to `False` in the output
- The Risk Scoring Engine (Phase 7) adjusts weights accordingly
- No alert is suppressed due to enrichment failure

---

## Modules

### `src/enrichment/ip_reputation.py`

```python
def check_ip_reputation(ip: str) -> dict:
    """
    Queries AbuseIPDB and VirusTotal for IP reputation.
    Returns: {"ip_reputation_score": int, "sources": dict}
    Cached with 1-hour TTL.
    """
```

### `src/enrichment/domain_reputation.py`

```python
def check_domain_reputation(domain: str) -> dict:
    """
    Queries VirusTotal for domain reputation.
    Returns: {"domain_reputation_score": int}
    Cached with 6-hour TTL.
    """
```

### `src/enrichment/ja3_lookup.py`

```python
def lookup_ja3(ja3_hash: str) -> dict:
    """
    Matches JA3 hash against local and community fingerprint databases.
    Returns: {"ja3_match": bool, "ja3_match_score": int, "ja3_threat_label": str | None}
    Cached with 24-hour TTL.
    """
```

### `src/enrichment/cert_checker.py`

```python
def assess_certificate(cert_fields: dict) -> dict:
    """
    Evaluates certificate risk from fields extracted during Phase 2/3.
    No external API call required.
    Returns: {"cert_risk_score": int}
    """
```

### `src/enrichment/intel_cache.py`

```python
# Shared TTLCache instances
ip_cache:     TTLCache
domain_cache: TTLCache
ja3_cache:    TTLCache
```

### `src/enrichment/enricher.py` (Orchestrator)

```python
def enrich(prediction: dict) -> dict:
    """
    Orchestrates all enrichment checks for a single ML-flagged flow.
    Calls ip_reputation, domain_reputation, ja3_lookup, cert_checker.
    Returns the enriched threat context dict.
    """
```

---

## Configuration (config.yaml)

```yaml
enrichment:
  enabled: true                       # Set to false to skip enrichment entirely
  abuseipdb_api_key: ""               # Loaded from .env
  virustotal_api_key: ""              # Loaded from .env
  ja3_database_path: "data/ja3_known_bad.json"
  request_timeout_sec: 5             # API request timeout
  ip_cache_ttl_sec: 3600             # 1 hour
  domain_cache_ttl_sec: 21600        # 6 hours
  ja3_cache_ttl_sec: 86400           # 24 hours
```

---

## Input / Output Summary

| Attribute | Details |
|---|---|
| **INPUT** | ML prediction dict (THREAT-classified flows only, from Phase 5) |
| **OUTPUT** | Enriched threat context dict (passed to Phase 7) |
| **When it runs** | Only when Phase 5 produces a THREAT classification |
| **Fallback** | Enrichment failure → neutral scores, flow still passes to Phase 7 |

---

## Technologies

| Component | Technology | Notes |
|---|---|---|
| IP reputation lookup | `requests` / `aiohttp` | AbuseIPDB + VirusTotal REST APIs |
| Domain reputation lookup | `requests` / `aiohttp` | VirusTotal REST API |
| JA3 matching | Python `json` + local lookup | Bundled community JA3 fingerprint database |
| Certificate assessment | Python (no external call) | Uses fields from Phase 2/3 |
| In-memory caching | `cachetools` | TTLCache for all external API results |
| API key management | `python-dotenv` | `.env` file, never committed to git |

---

## Deliverables

| File | Description |
|---|---|
| `src/enrichment/enricher.py` | Enrichment orchestrator — runs all checks for one flow |
| `src/enrichment/ip_reputation.py` | AbuseIPDB + VirusTotal IP lookup |
| `src/enrichment/domain_reputation.py` | VirusTotal domain lookup |
| `src/enrichment/ja3_lookup.py` | JA3 fingerprint database matching |
| `src/enrichment/cert_checker.py` | Certificate risk scoring from Phase 2/3 metadata |
| `src/enrichment/intel_cache.py` | Shared TTLCache instances |
| `src/enrichment/__init__.py` | Module init and exports |
| `data/ja3_known_bad.json` | Bundled community JA3 fingerprint database |
| `.env.example` | API key template (AbuseIPDB, VirusTotal) |

---

## Privacy Statement

> Phase 6 never transmits raw packet data or payload content to external services.
> Only IP addresses, domain names (SNI), and JA3 hashes are sent to reputation APIs.
> These values are derived exclusively from metadata extracted in Phases 2 and 3.
