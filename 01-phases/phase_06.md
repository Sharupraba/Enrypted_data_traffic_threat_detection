# Phase 6: Storage, Performance & Operations

> **Duration:** 2 weeks | **Depends on:** Phase 5 | **Feeds into:** Phase 7, Phase 8

---

## 1. Objective

Ensure the system can sustain continuous operation at production-scale throughput with full observability. Covers data storage architecture, message queue pipeline, capture performance, containerized deployment, and operational monitoring.

---

## 2. Tiered Storage Architecture

```
Live Detection Pipeline
        ↓
[HOT]   Redis 7          TTL:1h    JA3 lookup, dedup, enrichment cache, live features
        ↓
[WARM]  ClickHouse       TTL:30d   Flow records, dashboard aggregations, trend queries
        ↓
[COLD]  MinIO + Parquet  TTL:∞     Long-term archive, retraining corpus, forensics
[ALERTS] PostgreSQL      TTL:∞     Alert CRUD, analyst feedback, config, audit log
```

### 2.1 Redis — Hot Tier

```
Key namespaces:
  feature:{flow_id}           → Feature vector (TTL: 300s)
  enrich:{type}:{value}       → Threat intel cache (TTL: 1h or 24h)
  dedup:{hash}                → Alert dedup flag (TTL: per severity tier)
  ja3:{hash}                  → JA3 score (TTL: 24h)
  ratelimit:{ip}:{cat}        → Rate limit counter (TTL: 60s)
  baseline:{ip}:{metric}      → 7-day rolling baseline (TTL: 8h)
  stream:flows                → Redis Stream: raw flow records
  stream:alerts               → Redis Stream: triggered alerts
```

Config: `maxmemory: 4gb`, `maxmemory-policy: allkeys-lru`, persistence disabled (pure cache).

### 2.2 ClickHouse — Warm Tier

```sql
CREATE TABLE flows (
    flow_id         UUID,
    captured_at     DateTime,
    src_ip          IPv4,
    dst_ip          IPv4,
    src_port        UInt16,
    dst_port        UInt16,
    protocol        UInt8,
    flow_duration   Float32,
    total_bytes     UInt64,
    final_score_ml  Float32,
    alert_category  LowCardinality(String),
    ja3_hash        FixedString(32),
    sni             String,
    geo_country_dst LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(captured_at)
ORDER BY (captured_at, src_ip, dst_ip)
TTL captured_at + INTERVAL 30 DAY DELETE;
```

ETL: Background worker flushes Redis → ClickHouse every 6 hours.

### 2.3 MinIO + Parquet — Cold Tier

```
s3://ettd-cold/flows/year=2026/month=07/day=01/part-00001.parquet
s3://ettd-cold/retraining/confirmed_tp/     ← Analyst-confirmed true positives
s3://ettd-cold/retraining/confirmed_fp/     ← Analyst-confirmed false positives
s3://ettd-cold/retraining/benign/           ← Clean background traffic
```

The `retraining/` paths are consumed by Phase 8.

### 2.4 PostgreSQL — Alerts & Configuration

Core tables: `alerts`, `analyst_feedback`, `allowlist`, `model_versions`, `audit_log`.

Every alert status change, allow-list modification, model promotion, and analyst feedback is recorded immutably in `audit_log` with actor, timestamp, and before/after values.

---

## 3. Message Queue Pipeline

### 3.1 Development: Redis Streams
```
[Capture] → stream:flows → [Feature Worker] → stream:features
                                                      ↓
                                           [Detection Worker] → stream:alerts
                                                      ↓
                                          [Enrichment Worker] → PostgreSQL
```

### 3.2 Production: Apache Kafka
```
Topics: flows | features | alerts | enriched_alerts | analyst_feedback
Config: replication.factor=3, retention=24h, num.partitions=12
```

Switch via `MESSAGE_QUEUE=redis|kafka` in `.env` — no code changes required.

---

## 4. Capture Performance Tiers

| Tier | Technology | Throughput | Requirement |
|---|---|---|---|
| Development | NFStream / Scapy | 10–100 Mbps | Default |
| Standard | AF_PACKET + ring buffer | ~1 Gbps | Linux, CAP_NET_RAW |
| High Performance | PF_RING | 1–10 Gbps | Linux, kernel module |
| Line Rate | DPDK | 10–40+ Gbps | Bare-metal, DPDK NIC |

Default deployment: AF_PACKET covers most enterprise 1Gbps links.

---

## 5. Docker Compose Stack (Full Development)

Services: `postgres`, `redis`, `clickhouse`, `minio`, `backend`, `worker`, `enrichment_worker`, `frontend`, `prometheus`, `grafana`.

---

## 6. Prometheus Metrics

```
ettd_flows_captured_total               counter   Flows captured
ettd_inference_latency_seconds          histogram Model latency (p50/p95/p99)
ettd_alerts_generated_total             counter   By severity + category
ettd_alerts_suppressed_total            counter   Dedup/rate-limit suppressions
ettd_ensemble_score_distribution        histogram Score distribution (drift detection)
ettd_enrichment_cache_hits_total        counter   Redis enrichment cache hits
ettd_kafka_consumer_lag                 gauge     Kafka lag (alert if > 1000)
ettd_redis_memory_bytes                 gauge     Redis memory (alert at 80%)
```

---

## 7. Grafana Dashboards

**System Health:** Flows/sec, inference latency (p99), Kafka lag, Redis memory.

**Detection Statistics:** Alert volume by severity/category, FP rate trend from analyst feedback, score distribution histogram.

**Model Drift Monitor:** Rolling mean of `final_score_ml` for BENIGN flows. Drift > 5 points in 7 days = candidate for retraining trigger.

---

## 8. Deployment Path

```
Local Dev  →  docker-compose up (Redis Streams, all services)
Staging    →  Docker Compose on VM, AF_PACKET capture, external PostgreSQL
Production →  Kubernetes (Helm), Kafka, ClickHouse cluster, MinIO distributed
```

RBAC: JWT auth with `admin`, `analyst`, `read-only` roles. No secrets in env vars in production (use K8s Secrets or Vault).

---

## 9. Deliverables

| File | Description |
|---|---|
| `docker/Dockerfile.backend` | Backend image |
| `docker/Dockerfile.frontend` | Frontend Nginx image |
| `docker/docker-compose.yml` | Full development stack |
| `monitoring/prometheus.yml` | Prometheus config |
| `monitoring/grafana-dashboard.json` | Pre-built dashboards |
| `k8s/` | Helm chart skeleton |
| `src/storage/clickhouse_client.py` | CH async client + ETL |
| `src/storage/minio_client.py` | Parquet archive client |
| `src/queue/redis_streams.py` | Redis Streams producer/consumer |
| `src/queue/kafka_client.py` | Kafka producer/consumer |

---

## 10. Acceptance Criteria

- [ ] `docker-compose up` brings full stack online with no manual config.
- [ ] Inference p99 < 50ms at 500 flows/sec simulated load.
- [ ] ClickHouse top-10 SrcIP query < 1s on 10M rows.
- [ ] MinIO Parquet partitions populated within 7 hours (ETL).
- [ ] Kafka lag alert fires when lag > 1000.
- [ ] `MESSAGE_QUEUE=redis|kafka` switches cleanly without code changes.
- [ ] All audit events logged with actor + timestamp.
