# Performance Baseline Results (Plan 1.10)

**Date:** 2026-03-27
**Tool:** Locust 2.x
**Config:** 20 users, ramp rate 5/sec, duration 30s
**Target:** http://localhost:8001 (Docker dev stack)

## Run Command

```bash
cd backend && .venv/bin/locust -f tests/performance/locustfile.py \
    --headless -u 20 -r 5 -t 30s --host http://localhost:8001
```

## Results

> Populate this section after running the baseline test.
> Paste the Locust summary table output below.

```
 Name                          # reqs      # fails |    Avg     Min     Max    Med |   req/s  failures/s
------------------------------------------------------------------------------------------------
 GET /api/v1/admin/settings         -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/users            -          -   |      -       -       -      - |       -          -
 GET /api/v1/assets?...             -          -   |      -       -       -      - |       -          -
 GET /api/v1/health                 -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/compliance   -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/quantum      -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/summary      -          -   |      -       -       -      - |       -          -
 POST /api/v1/auth/login            -          -   |      -       -       -      - |       -          -
------------------------------------------------------------------------------------------------

Response time percentiles (approximated)
 Type     Name                          50%    66%    75%    80%    90%    95%    98%    99%  99.9% 99.99%   100% # reqs
--------|------------------------------|------|------|------|------|------|------|------|------|------|------|------|------
--------|------------------------------|------|------|------|------|------|------|------|------|------|------|------|------
```

## Targets (Phase 4.5)

| Endpoint                    | p50 target | p95 target | p99 target |
|-----------------------------|-----------|-----------|-----------|
| GET /api/v1/health          | < 20ms    | < 50ms    | < 100ms   |
| GET /api/v1/portfolio/*     | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/assets          | < 150ms   | < 400ms   | < 700ms   |
| GET /api/v1/admin/*         | < 100ms   | < 300ms   | < 500ms   |
| POST /api/v1/auth/login     | < 200ms   | < 500ms   | < 800ms   |

## Notes

- Auth login includes bcrypt password verification, so higher latency is expected.
- Portfolio endpoints hit Redis cache after first request; first-call latency may be higher.
- Admin endpoints require org_admin/security_manager role; 403 responses indicate role mismatch.
- 401 responses on authenticated endpoints indicate token extraction issues.
- 404/422 responses may indicate endpoints not yet wired or missing query params.

---

# Performance Baseline Results (Plan 2 — Finding Workflow)

**Date:** 2026-03-27
**Tool:** Locust 2.x
**Config:** 50 users, ramp rate 10/sec, duration 60s
**Target:** http://localhost:8001 (Docker dev stack)

## Run Command

```bash
cd backend && .venv/bin/locust -f tests/performance/locustfile.py \
    --headless -u 50 -r 10 -t 60s --host http://localhost:8001
```

## New Endpoints Added (Plan 2)

| Endpoint                                             | Method | Weight | Description                   |
|------------------------------------------------------|--------|--------|-------------------------------|
| `/api/v1/projects/:id/findings?...`                  | GET    | 3      | Paginated findings with filters |
| `/api/v1/findings/:id/status`                        | PATCH  | 1      | Transition finding status     |
| `/api/v1/findings/:id/history`                       | GET    | 1      | Finding audit trail           |
| `/api/v1/requests?page=1&per_page=25`                | GET    | 1      | FP review request queue       |
| `/api/v1/admin/rules/:id/analytics?time_window=90d`  | GET    | 1      | Rule-level analytics          |

## Results

> Populate this section after running the load test against the dev stack.
> Start the dev stack with `docker compose -f deploy/docker-compose.yml up`, then run the command above.

```
 Name                                                  # reqs      # fails |    Avg     Min     Max    Med |   req/s  failures/s
------------------------------------------------------------------------------------------------------------------------------
 GET /api/v1/admin/rules/.../analytics?time_window=90d      -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/settings                                 -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/users                                    -          -   |      -       -       -      - |       -          -
 GET /api/v1/assets?...                                     -          -   |      -       -       -      - |       -          -
 GET /api/v1/findings/.../history                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/health                                         -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/compliance                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/quantum                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/summary                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/projects/.../findings?...                      -          -   |      -       -       -      - |       -          -
 GET /api/v1/requests?...                                   -          -   |      -       -       -      - |       -          -
 PATCH /api/v1/findings/.../status                          -          -   |      -       -       -      - |       -          -
 POST /api/v1/auth/login                                    -          -   |      -       -       -      - |       -          -
------------------------------------------------------------------------------------------------------------------------------
```

## Targets (Phase 4.5 — Plan 2 Finding Endpoints)

| Endpoint                                   | p50 target | p95 target | p99 target |
|--------------------------------------------|-----------|-----------|-----------|
| GET /api/v1/projects/:id/findings          | < 150ms   | < 400ms   | < 700ms   |
| PATCH /api/v1/findings/:id/status          | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/findings/:id/history           | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/requests                       | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/admin/rules/:id/analytics      | < 200ms   | < 500ms   | < 800ms   |

## Notes

- Finding list endpoint has weight 3 (most frequently hit) to simulate real dashboard usage.
- Status change is a write operation; expect higher latency than reads.
- Rule analytics may be slow on first call due to aggregation; subsequent calls benefit from caching.
- Requests endpoint returns paginated FP review queue; filters by org via RLS.
- Finding history is an audit log query; may benefit from TimescaleDB time-range pruning.

---

# Performance Baseline Results (Plan 3 — Scan Lifecycle)

**Date:** 2026-03-27
**Tool:** Locust 2.x
**Config:** 50 users, ramp rate 10/sec, duration 60s
**Target:** http://localhost:8001 (Docker dev stack)

## Run Command

```bash
cd backend && .venv/bin/locust -f tests/performance/locustfile.py \
    --headless -u 50 -r 10 -t 60s --host http://localhost:8001
```

## New Endpoints Added (Plan 3)

| Endpoint                                     | Method | Weight | Description                     |
|----------------------------------------------|--------|--------|---------------------------------|
| `/api/v1/scans?page=1&per_page=25&status=running` | GET | 2      | Paginated scan queue with filter |
| `/api/v1/projects/:id/schedule`              | GET    | 1      | Project scan schedule           |
| `/api/v1/scans/:id/provenance`               | GET    | 1      | Scan provenance metadata        |
| `/api/v1/admin/registries`                   | GET    | 1      | Artifact registry list          |
| `/api/v1/admin/environments`                 | GET    | 1      | Environment list                |

## Results

> Populate this section after running the load test against the dev stack.
> Start the dev stack with `docker compose -f deploy/docker-compose.yml up`, then run the command above.

```
 Name                                                  # reqs      # fails |    Avg     Min     Max    Med |   req/s  failures/s
------------------------------------------------------------------------------------------------------------------------------
 GET /api/v1/admin/environments                             -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/registries                               -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/rules/.../analytics?time_window=90d      -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/settings                                 -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/users                                    -          -   |      -       -       -      - |       -          -
 GET /api/v1/assets?...                                     -          -   |      -       -       -      - |       -          -
 GET /api/v1/findings/.../history                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/health                                         -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/compliance                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/quantum                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/summary                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/projects/.../findings?...                      -          -   |      -       -       -      - |       -          -
 GET /api/v1/projects/.../schedule                          -          -   |      -       -       -      - |       -          -
 GET /api/v1/requests?...                                   -          -   |      -       -       -      - |       -          -
 GET /api/v1/scans?...                                      -          -   |      -       -       -      - |       -          -
 GET /api/v1/scans/.../provenance                           -          -   |      -       -       -      - |       -          -
 PATCH /api/v1/findings/.../status                          -          -   |      -       -       -      - |       -          -
 POST /api/v1/auth/login                                    -          -   |      -       -       -      - |       -          -
------------------------------------------------------------------------------------------------------------------------------
```

## Targets (Phase 4.5 — Plan 3 Scan Lifecycle Endpoints)

| Endpoint                              | p50 target | p95 target | p99 target |
|---------------------------------------|-----------|-----------|-----------|
| GET /api/v1/scans                     | < 150ms   | < 400ms   | < 700ms   |
| GET /api/v1/projects/:id/schedule     | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/scans/:id/provenance      | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/admin/registries          | < 100ms   | < 300ms   | < 500ms   |
| GET /api/v1/admin/environments        | < 100ms   | < 300ms   | < 500ms   |

## Notes

- Scan queue endpoint has weight 2 (frequently polled by dashboard) to simulate real usage.
- Schedule endpoint uses fake project ID; 404 responses indicate the project does not exist.
- Provenance endpoint uses fake scan ID; 404 responses indicate the scan does not exist.
- Registries and environments are admin-only endpoints; 403 responses indicate role mismatch.
- All new endpoints benefit from Redis caching after initial cold call.

---

# Performance Baseline Results (Plan 7 — Portfolio Views)

**Date:** 2026-03-27
**Tool:** Locust 2.x
**Config:** 50 users, ramp rate 10/sec, duration 60s
**Target:** http://localhost:8001 (Docker dev stack)

## Run Command

```bash
cd backend && .venv/bin/locust -f tests/performance/locustfile.py \
    --headless -u 50 -r 10 -t 60s --host http://localhost:8001
```

## New Endpoints Added (Plan 7)

| Endpoint                                              | Method | Weight | Description                    |
|-------------------------------------------------------|--------|--------|--------------------------------|
| `/api/v1/portfolio/certificates?page=1&per_page=25`   | GET    | 1      | Paginated certificate tracker  |
| `/api/v1/portfolio/pqc-migration`                     | GET    | 1      | PQC migration status           |

## Results

> Populate this section after running the load test against the dev stack.
> Start the dev stack with `docker compose -f deploy/docker-compose.yml up`, then run the command above.

```
 Name                                                  # reqs      # fails |    Avg     Min     Max    Med |   req/s  failures/s
------------------------------------------------------------------------------------------------------------------------------
 GET /api/v1/admin/environments                             -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/registries                               -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/rules/.../analytics?time_window=90d      -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/settings                                 -          -   |      -       -       -      - |       -          -
 GET /api/v1/admin/users                                    -          -   |      -       -       -      - |       -          -
 GET /api/v1/assets?...                                     -          -   |      -       -       -      - |       -          -
 GET /api/v1/findings/.../history                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/health                                         -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/certificates?...                     -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/compliance                           -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/pqc-migration                        -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/quantum                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/portfolio/summary                              -          -   |      -       -       -      - |       -          -
 GET /api/v1/projects/.../findings?...                      -          -   |      -       -       -      - |       -          -
 GET /api/v1/projects/.../schedule                          -          -   |      -       -       -      - |       -          -
 GET /api/v1/requests?...                                   -          -   |      -       -       -      - |       -          -
 GET /api/v1/scans?...                                      -          -   |      -       -       -      - |       -          -
 GET /api/v1/scans/.../provenance                           -          -   |      -       -       -      - |       -          -
 PATCH /api/v1/findings/.../status                          -          -   |      -       -       -      - |       -          -
 POST /api/v1/auth/login                                    -          -   |      -       -       -      - |       -          -
------------------------------------------------------------------------------------------------------------------------------
```

## Targets (Phase 4.5 — Plan 7 Portfolio View Endpoints)

| Endpoint                                | p50 target | p95 target | p99 target |
|-----------------------------------------|-----------|-----------|-----------|
| GET /api/v1/portfolio/certificates      | < 150ms   | < 400ms   | < 700ms   |
| GET /api/v1/portfolio/pqc-migration     | < 100ms   | < 300ms   | < 500ms   |

## Notes

- Certificate tracker endpoint returns paginated list with expiry status badges; benefits from Redis cache.
- PQC migration endpoint aggregates algorithm migration progress across the portfolio.
- Both endpoints are read-only and scoped to the authenticated user's org via RLS.
- 401 responses on these endpoints indicate token extraction issues.
- 404 responses may indicate endpoints not yet wired.
