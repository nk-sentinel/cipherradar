# Phase 4.5 — Plan 7: Portfolio Views — Detailed Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Certificate tracker and PQC migration progress views. Final performance benchmark.

**Decisions:** D23 (cert tracker, PQC migration progress)

---

## Agent Assignment

| Agent | Tasks |
|---|---|
| **Backend + Frontend** | 7.1, 7.2, 7.3, 7.4 |
| **E2E + Perf** | 7.5, 7.6 |

---

## Task 7.1: Backend — Certificate Tracker API

**Create:**
- `backend/app/services/certificate_tracker_service.py` — query all certificate findings across projects, compute expiry status (green >90d, amber 30-90d, red <30d, black expired), group by project
- `backend/app/schemas/certificate_tracker.py` — CertificateEntry(id, subject, issuer, not_after, status_color, project_name, project_id, days_remaining)
- `backend/app/api/v1/certificates_tracker.py` — GET /portfolio/certificates (paginated, filterable by status/project)
- `backend/tests/services/test_certificate_tracker_service.py`

Roles: all authenticated users (results scoped by group access per D12).

Tests: test_expiry_color_coding, test_expired_cert, test_upcoming_expiry, test_healthy_cert, test_grouped_by_project

Commit: `feat: add certificate tracker API (D23)`

## Task 7.2: Frontend — Certificate Tracker Page (D23 #48)

**Create:**
- `frontend/src/pages/CertificateTracker.tsx` — timeline/calendar view of cert expiry dates, color-coded rows, filter by project/status, pagination
- `frontend/src/api/hooks/useCertificateTracker.ts`
- `frontend/tests/pages/CertificateTracker.test.tsx`

**Modify:**
- `frontend/src/router.tsx` — add /certificates route
- `frontend/src/components/layout/Sidebar.tsx` — add "Certificate Tracker" under Portfolio section

Commit: `feat: add certificate tracker page (D23)`

## Task 7.3: Backend — PQC Migration Progress API

**Create:**
- `backend/app/services/pqc_migration_service.py` — aggregate migration posture: % quantum-vulnerable across org, per-algorithm-family progress (RSA→ML-KEM, ECDSA→ML-DSA, AES-128→AES-256, SHA-1→SHA-256, etc.), lagging projects, on-track indicator vs quantum deadline from org settings
- `backend/app/schemas/pqc_migration.py` — MigrationOverview(pct_vulnerable, pct_safe, pct_unknown), AlgorithmFamilyProgress(family, current, target, not_started, in_progress, complete, project_count), LaggingProject(id, name, vulnerable_count)
- `backend/app/api/v1/pqc_migration.py` — GET /portfolio/pqc-migration
- `backend/tests/services/test_pqc_migration_service.py`

Tests: test_percentage_calculation, test_algorithm_family_grouping, test_lagging_projects, test_empty_org

Commit: `feat: add PQC migration progress API (D23)`

## Task 7.4: Frontend — PQC Migration Progress (D23 #49)

This is a read-only dashboard section within Portfolio Compliance — NOT a separate page.

**Create:**
- `frontend/src/components/compliance/PQCMigrationProgress.tsx` — progress bars by algorithm family, project counts per stage (Not Started/In Progress/Complete), overall % safe/vulnerable/unknown donut chart, lagging projects list, on-track indicator
- `frontend/src/api/hooks/usePQCMigration.ts`
- `frontend/tests/components/PQCMigrationProgress.test.tsx`

**Modify:**
- `frontend/src/pages/Compliance.tsx` (or Portfolio Compliance page) — add PQCMigrationProgress section

Uses Recharts for donut chart and bar charts.

Commit: `feat: add PQC migration progress section in portfolio compliance (D23)`

## Task 7.5: E2E — Portfolio Tests

**Create:** `frontend/e2e/portfolio-views.spec.ts`

Scenarios:
1. Certificate tracker page loads with cert table
2. Certificate color coding visible (green/amber/red)
3. Compliance page shows PQC migration section
4. PQC progress bars render
5. Portfolio pages have no accessibility violations

Commit: `test: add portfolio views E2E tests`

## Task 7.6: Performance — Final Benchmark

**Modify:** `backend/tests/performance/locustfile.py` — add certificate tracker and PQC migration tasks

Run final benchmark: 100 concurrent users, 5 min duration. Compare against Plan 1 baseline.

Update `backend/tests/performance/baseline-results.md` — append final Plan 7 comparison.

Commit: `perf: add final performance benchmark`
