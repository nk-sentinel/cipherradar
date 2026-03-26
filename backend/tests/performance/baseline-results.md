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
