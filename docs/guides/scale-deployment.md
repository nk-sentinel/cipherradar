# Scale Deployment Guide

This guide covers configuring CipherRadar for organisations managing 50+ repositories, including worker scaling, queue tuning, database connection pooling, and resource planning.

## Architecture Overview at Scale

At scale, CipherRadar follows a horizontally scalable architecture:

```
                    ┌─────────────┐
                    │   Ingress    │
                    │   (TLS 1.3) │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴───┐ ┌─────┴──────┐
        │ FastAPI    │ │ React │ │ FastAPI    │
        │ Replicas   │ │  SPA  │ │ Replicas   │
        │ (2-8)      │ │       │ │ (2-8)      │
        └─────┬──────┘ └───────┘ └─────┬──────┘
              │                         │
        ┌─────┴─────────────────────────┴─────┐
        │            Redis Cluster             │
        │      (scan queue + pub/sub)          │
        └─────────────────┬────────────────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
        ┌─────┴────┐ ┌───┴────┐ ┌───┴─────┐
        │  Taskiq   │ │ Taskiq │ │ Taskiq  │
        │ Worker 1  │ │ Worker │ │ Worker  │
        │           │ │   2    │ │   N     │
        └─────┬─────┘ └───┬────┘ └───┬─────┘
              │            │          │
        ┌─────┴────────────┴──────────┴─────┐
        │         PostgreSQL                 │
        │    (PgBouncer connection pool)     │
        └───────────────────────────────────┘
```

## Worker Scaling (Taskiq)

### Configuration

Each Taskiq worker runs in its own process and can handle one scan at a time. Scale workers to match your desired scan parallelism.

Environment variables for worker configuration:

```bash
# Number of worker processes per pod
CBOM_WORKER_CONCURRENCY=4

# Maximum scan duration before timeout (seconds)
CBOM_SCAN_TIMEOUT=600

# Per-project concurrency limit (prevents one project from starving others)
CBOM_MAX_CONCURRENT_SCANS_PER_PROJECT=2
```

### Kubernetes HPA

Deploy workers as a Kubernetes Deployment with Horizontal Pod Autoscaler:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cipherradar-worker
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cipherradar-worker
  template:
    metadata:
      labels:
        app: cipherradar-worker
    spec:
      containers:
        - name: worker
          image: cipherradar/worker:latest
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2000m"
              memory: "4Gi"
          env:
            - name: CBOM_REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: cipherradar-secrets
                  key: redis-url
            - name: CBOM_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: cipherradar-secrets
                  key: database-url
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: cipherradar-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: cipherradar-worker
  minReplicas: 2
  maxReplicas: 20
  metrics:
    # Scale based on Redis queue depth (via Prometheus adapter)
    - type: External
      external:
        metric:
          name: cipherradar_queue_depth
        target:
          type: AverageValue
          averageValue: "5"
    # Also scale on CPU as a safety net
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Worker sizing guidance

Each scan worker needs enough memory to hold the tree-sitter AST and OpenGrep results for the largest file in the scanned repository. For most codebases:

- Small repos (< 10k lines): 512 MB per worker
- Medium repos (10k-100k lines): 1 GB per worker
- Large repos (100k+ lines): 2-4 GB per worker
- Monorepos with vendored dependencies: 4-8 GB per worker

## Redis Tuning

Redis serves two roles: scan job queue (Taskiq broker) and notification Pub/Sub.

### Recommended configuration

```conf
# redis.conf additions for CipherRadar at scale

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence — AOF for durability (scan jobs must survive restarts)
appendonly yes
appendfsync everysec

# Connection limits
maxclients 10000

# Timeout for idle connections (workers reconnect automatically)
timeout 300

# TCP keepalive
tcp-keepalive 60
```

### Redis Sentinel or Cluster

For 50+ repos, run Redis Sentinel (3 nodes minimum) for high availability:

```bash
CBOM_REDIS_URL=redis+sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster/0
```

For 500+ repos or heavy Pub/Sub load, consider Redis Cluster with 3+ shards.

### Queue monitoring

Key Redis metrics to watch:

- `cipherradar:scan_queue` list length (target: < 50 pending jobs)
- Connected clients count
- Memory usage relative to `maxmemory`
- Pub/Sub channels count (one per active WebSocket session)

## PostgreSQL Connection Pooling

### PgBouncer

At scale, use PgBouncer between the application and PostgreSQL to manage connection pooling:

```ini
; pgbouncer.ini

[databases]
cipherradar = host=postgres port=5432 dbname=cipherradar

[pgbouncer]
listen_port = 6432
listen_addr = 0.0.0.0

; Transaction-mode pooling (required for async SQLAlchemy)
pool_mode = transaction

; Pool sizing
default_pool_size = 25
max_client_conn = 200
min_pool_size = 5
reserve_pool_size = 5
reserve_pool_timeout = 3

; Timeouts
server_idle_timeout = 600
client_idle_timeout = 0
query_timeout = 300

; Authentication
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
```

Update the application database URL to point to PgBouncer:

```bash
CBOM_DATABASE_URL=postgresql+asyncpg://postgres:password@pgbouncer:6432/cipherradar
```

### SQLAlchemy engine settings

In the application configuration, tune the async engine pool:

```bash
# Pool size should be less than PgBouncer default_pool_size
# to leave headroom for workers
CBOM_DB_POOL_SIZE=10
CBOM_DB_MAX_OVERFLOW=20
CBOM_DB_POOL_TIMEOUT=30
CBOM_DB_POOL_RECYCLE=1800
```

### PostgreSQL server tuning

Key `postgresql.conf` settings for CipherRadar at scale:

```conf
# Connections (set high if using PgBouncer)
max_connections = 200

# Memory
shared_buffers = 4GB          # 25% of available RAM
effective_cache_size = 12GB   # 75% of available RAM
work_mem = 64MB
maintenance_work_mem = 512MB

# WAL
wal_buffers = 64MB
max_wal_size = 4GB
checkpoint_completion_target = 0.9

# Query planner
random_page_cost = 1.1        # SSD storage
effective_io_concurrency = 200 # SSD storage
```

## Resource Requirements by Scale Tier

### 10 Repositories (Starter)

| Component       | Replicas | CPU (request/limit) | Memory (request/limit) |
|----------------|----------|---------------------|----------------------|
| FastAPI         | 1        | 250m / 500m         | 256Mi / 512Mi        |
| Taskiq Worker   | 1        | 500m / 1000m        | 512Mi / 1Gi          |
| Redis           | 1        | 100m / 250m         | 128Mi / 256Mi        |
| PostgreSQL      | 1        | 250m / 500m         | 512Mi / 1Gi          |
| **Total**       |          | **1.1 / 2.25 CPU**  | **1.4 / 2.75 Gi**   |

### 50 Repositories (Team)

| Component       | Replicas | CPU (request/limit) | Memory (request/limit) |
|----------------|----------|---------------------|----------------------|
| FastAPI         | 2        | 500m / 1000m        | 512Mi / 1Gi          |
| Taskiq Worker   | 4        | 500m / 2000m        | 1Gi / 4Gi            |
| Redis Sentinel  | 3        | 250m / 500m         | 512Mi / 1Gi          |
| PostgreSQL      | 1        | 1000m / 2000m       | 2Gi / 4Gi            |
| PgBouncer       | 1        | 100m / 250m         | 64Mi / 128Mi         |
| **Total**       |          | **5.35 / 12.75 CPU**| **8.6 / 22.1 Gi**   |

### 100 Repositories (Growth)

| Component       | Replicas | CPU (request/limit) | Memory (request/limit) |
|----------------|----------|---------------------|----------------------|
| FastAPI         | 3        | 500m / 1000m        | 512Mi / 1Gi          |
| Taskiq Worker   | 8        | 500m / 2000m        | 1Gi / 4Gi            |
| Redis Sentinel  | 3        | 500m / 1000m        | 1Gi / 2Gi            |
| PostgreSQL      | 1 primary + 1 replica | 2000m / 4000m | 4Gi / 8Gi   |
| PgBouncer       | 2        | 100m / 250m         | 64Mi / 128Mi         |
| **Total**       |          | **11.2 / 28.5 CPU** | **17.6 / 52.3 Gi**  |

### 500 Repositories (Enterprise)

| Component       | Replicas | CPU (request/limit) | Memory (request/limit) |
|----------------|----------|---------------------|----------------------|
| FastAPI         | 6        | 1000m / 2000m       | 1Gi / 2Gi            |
| Taskiq Worker   | 20       | 1000m / 2000m       | 2Gi / 4Gi            |
| Redis Cluster   | 6        | 500m / 1000m        | 2Gi / 4Gi            |
| PostgreSQL      | 1 primary + 2 replicas | 4000m / 8000m | 8Gi / 16Gi |
| PgBouncer       | 2        | 250m / 500m         | 128Mi / 256Mi        |
| **Total**       |          | **39.5 / 82 CPU**   | **77.3 / 168.5 Gi** |

## Scan Throughput Estimates

With default scan timeout of 10 minutes per repository:

| Scale Tier | Workers | Parallel Scans | Full Portfolio Scan Time |
|-----------|---------|----------------|------------------------|
| 10 repos  | 1       | 1              | ~100 minutes           |
| 50 repos  | 4       | 4              | ~125 minutes           |
| 100 repos | 8       | 8              | ~125 minutes           |
| 500 repos | 20      | 20             | ~250 minutes           |

These estimates assume average scan time of 10 minutes per repo. Actual times vary significantly by repository size, language mix, and detection pass configuration.

## Monitoring at Scale

Ensure the `/api/v1/metrics` Prometheus endpoint is scraped and alert on:

- `cipherradar_queue_depth` > 100 for more than 5 minutes (scale workers up)
- `cipherradar_active_scans` near worker count for sustained periods (saturated)
- `cipherradar_scan_duration_seconds` p99 > 600s (scans timing out)
- PostgreSQL connection pool exhaustion (PgBouncer `cl_waiting` > 0)
- Redis memory usage > 80% of `maxmemory`

See [SOC 2 Controls](soc2-controls.md) for audit logging and compliance monitoring requirements.
