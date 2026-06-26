# Phase 4: Threat Intelligence Integration

> **Duration:** 1 week  
> **Status:** Not started  
> **Depends on:** Phase 3 (ensemble score available)  
> **Feeds into:** Phase 5 (Alert Engine)

---

## 1. Objective

Enrich each ML-generated detection with **external threat context** from real-world intelligence sources. This layer serves two purposes:
1. **Increase precision:** Correlating an ML detection with external IOC confirmation dramatically reduces false positives (e.g., a Medium-confidence ML alert + VirusTotal hit → escalate to High).
2. **Reduce analyst workload:** Providing MITRE ATT&CK TTP tags, reputation scores, and historical context directly in the alert removes the need for manual lookups.

The enrichment layer is **asynchronous and cached**. It never blocks the main detection pipeline. Enrichment happens after the initial alert is raised, and the alert is updated in-place when enrichment completes.

---

## 2. Intelligence Sources

### 2.1 IP Reputation

| Source | Data | Rate Limit (Free) | Auth |
|---|---|---|---|
| AbuseIPDB | Abuse confidence %, report count, usage type | 1,000 req/day | API key |
| VirusTotal | Detection ratio (N/72 engines), community score | 500 req/day | API key |
| Shodan | Open ports, banners, known CVEs, hosting provider | 1 req/sec | API key |

**AbuseIPDB Response Mapping:**
```
abuseConfidenceScore ≥ 75  → ip_reputation = 1.0 (confirmed malicious)
abuseConfidenceScore 30–74 → ip_reputation = 0.6 (suspicious)
abuseConfidenceScore < 30  → ip_reputation = 0.1 (likely clean)
```

**Shodan Supplemental Context:**  
Useful for answering "Is this IP a Tor exit node?", "Is it a known VPN/proxy?", or "Does it have open RDP/SMB ports that indicate a compromised host?". This context is added to the alert metadata but does not directly modify the score.

### 2.2 Domain Intelligence

| Source | Data | Notes |
|---|---|---|
| AlienVault OTX | Domain pulses, threat categories, associated IOCs | Free API |
| Cisco Umbrella | Domain risk score, category | Requires Umbrella subscription |
| Quad9 | Real-time blocking signal | Query `dns.quad9.net` with the SNI domain |
| Newly Registered Domains feeds | Domain age < 30 days | Check WhoisXML or DomainTools API |

**Quad9 Integration:**  
Instead of a REST API, Quad9 querying works as follows:
```python
import dns.resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['9.9.9.9']
try:
    resolver.resolve(suspicious_domain, 'A')
    # Quad9 resolved it → not on their blocklist
except NXDOMAIN:
    # Quad9 blocked it → confirmed malicious domain
```

### 2.3 TLS Intelligence

| Source | Data | Update Frequency |
|---|---|---|
| Salesforce JA3 DB | Known malicious JA3 hashes | Updated irregularly — sync weekly |
| ja3er.com | Community JA3 submissions | Daily sync |
| JARM (Active) | Server fingerprinting | **On-demand analyst probe only** (see §2.3.1) |
| crt.sh | Certificate transparency history | REST: `https://crt.sh/?q=<domain>&output=json` |

#### 2.3.1 JARM — Active Investigation Module

> **JARM is not a passive feature.** It requires sending 10 crafted TLS ClientHello packets to the target server and analyzing the ServerHello responses. This cannot be computed from captured traffic — it requires **active outbound connections** from the sensor.

**Architecture:** JARM lives exclusively in `src/threat_intel/jarm_probe.py` and is triggered **manually by an analyst** from the Flow Inspector dashboard. When an analyst clicks "Probe with JARM" on a suspicious destination IP:

1. The backend sends 10 crafted TLS ClientHellos to the destination IP.
2. The JARM hash is computed from the ServerHello responses.
3. The hash is looked up against the JARM database.
4. The result is appended to the alert as an investigation note.

**Security consideration:** Active JARM probing reveals that your sensor is investigating the destination. Use only when the analyst is comfortable with this disclosure. This option is **disabled by default** and requires admin role to enable.

---

## 3. Enrichment Pipeline Architecture

```
Detection Alert Created (ensemble score computed)
          ↓
[Alert Engine]  →  Publish to Redis Stream: "enrichment:queue"
                                   ↓
                      [Enrichment Worker] (async, separate process)
                        ├── extract src_ip, dst_ip, sni, ja3_hash from alert
                        │
                        ├── CHECK Redis cache: f"enrich:{ip}:{type}"
                        │    ├── CACHE HIT  → return cached result immediately
                        │    └── CACHE MISS → call external API
                        │
                        ├── Async API calls (in parallel, max 3s timeout):
                        │    ├── AbuseIPDB(dst_ip)
                        │    ├── VirusTotal(dst_ip or sni)
                        │    └── OTX(sni or ja3_hash)
                        │
                        ├── Store results in Redis (TTL: 1 hour)
                        │
                        ├── MITRE ATT&CK Tagging
                        │
                        └── UPDATE alert in PostgreSQL with enrichment data
```

**Timeout policy:** If all API calls do not complete within 3 seconds, the alert is stored with `enrichment_status: "pending"` and enrichment continues in the background. The alert is written to the dashboard immediately without waiting.

**Rate limit management:**
- A Redis token bucket enforces per-API rate limits.
- AbuseIPDB: 1,000 req/day → ~0.7 req/min → enforce 1 req/min hard cap.
- If a burst of alerts hits the same destination IP, all subsequent alerts get the cached result — the API is called only once per IP per TTL window.

---

## 4. Redis Cache Design

```
Key format:    enrich:{lookup_type}:{value}
Example:       enrich:ip:185.220.101.1
               enrich:domain:malware.example.com
               enrich:ja3:e7d705a3286e19ea42f587b344ee6865

TTL:  3600 seconds (1 hour) for negative results
      86400 seconds (24 hours) for confirmed malicious (positive) results
      Positive results are cached longer because malicious infrastructure rarely flips clean within 24h.

Value format:
{
    "ip_reputation": 0.92,
    "abuse_confidence": 87,
    "vt_malicious": 12,
    "vt_total": 72,
    "shodan_tags": ["proxy", "vpn"],
    "otx_pulses": 3,
    "domain_risk": 0.85,
    "is_newly_registered": true,
    "quad9_blocked": true,
    "enriched_at": "2026-07-01T12:00:00Z"
}
```

---

## 5. MITRE ATT&CK Mapping

The `mitre_mapper.py` module maps internal threat categories to MITRE ATT&CK techniques using a static rules-based mapping (no ML). The STIX bundle is downloaded from `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` and stored locally.

| Internal Category | ATT&CK Technique | Technique ID |
|---|---|---|
| C2_BEACONING | Application Layer Protocol: Web Protocols | T1071.001 |
| DNS_TUNNELING | Application Layer Protocol: DNS | T1071.004 |
| PROTOCOL_TUNNELING | Protocol Tunneling | T1572 |
| DATA_EXFILTRATION | Exfiltration Over C2 Channel | T1041 |
| PORT_SCAN | Network Service Discovery | T1046 |
| LATERAL_MOVEMENT | Lateral Tool Transfer | T1570 |
| MALWARE_STAGING | Ingress Tool Transfer | T1105 |
| TLS_MALWARE | Encrypted Channel | T1573 |
| DGA_MALWARE | Domain Generation Algorithms | T1568.002 |

**Multi-technique alerts:** A single flow can match multiple techniques. Example: a C2 beacon using DGA domains gets tagged `[T1071.001, T1568.002]`.

---

## 6. Alert Score Escalation

External enrichment can **upgrade** (but not downgrade) an alert's severity:

| Condition | Score Modifier |
|---|---|
| AbuseIPDB confidence ≥ 75 | +15 |
| VirusTotal malicious detections ≥ 5/72 | +10 |
| Quad9 blocked domain | +20 |
| Domain registered < 30 days | +5 |
| Shodan tagged as Tor exit node | +25 |
| OTX pulse match | +10 |

Score modifiers are additive and capped at 100. The modified score is stored as `final_score_enriched` alongside the original `final_score_ml`.

---

## 7. Deliverables

| File | Description |
|---|---|
| `src/threat_intel/ip_reputation.py` | AbuseIPDB, VirusTotal, Shodan clients |
| `src/threat_intel/domain_intel.py` | OTX, Umbrella, Quad9, domain age clients |
| `src/threat_intel/ja3_lookup.py` | Salesforce/ja3er hash database sync + lookup |
| `src/threat_intel/jarm_probe.py` | Active JARM probing module (analyst-triggered) |
| `src/threat_intel/cert_inspector.py` | crt.sh certificate history lookup |
| `src/threat_intel/intel_cache.py` | Redis cache manager with TTL logic |
| `src/threat_intel/enrichment_worker.py` | Async enrichment pipeline worker |
| `src/detection/mitre_mapper.py` | Static ATT&CK TTP tagging rules |

---

## 8. Acceptance Criteria

- [ ] JARM probe is accessible ONLY via `jarm_probe.py`, completely absent from passive capture or feature modules.
- [ ] Enrichment completes within 3 seconds for cached results.
- [ ] AbuseIPDB rate limiting enforced (max 1 req/min) and verified by test.
- [ ] Alert written to DB immediately; enrichment updated async — confirmed by integration test.
- [ ] MITRE tags present in 100% of alerts (at minimum, tags derived from internal category).
- [ ] Positive cache TTL (24h) vs negative TTL (1h) verified.
- [ ] Redis keys follow the defined `enrich:{type}:{value}` format.
