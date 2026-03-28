# Phase 4.5 — Post-Implementation Bug Tracker

> **Created:** 2026-03-28
> **Status:** Active — post-implementation review in progress

---

## HIGH Priority

### BUG-001: Scanner Worker Crash Loop
- **Status:** OPEN
- **Severity:** HIGH
- **Component:** `deploy/scanner-worker/`
- **Error:** `AttributeError: module 'app.workers.scan_worker' has no attribute 'broker'`
- **Impact:** Scanner worker container restarts in a loop. No scans can be triggered.
- **Root cause:** Taskiq broker import path mismatch. Worker Dockerfile starts `taskiq worker app.workers.scan_worker:broker` but the module doesn't export `broker`.
- **Pre-existing:** Yes — not caused by Phase 4.5 changes.

---

## MEDIUM Priority

### BUG-002: Frontend API Response Shape Mismatches
- **Status:** PARTIALLY FIXED
- **Severity:** MEDIUM
- **Component:** `frontend/src/api/hooks/`
- **Issue:** Multiple hooks expect raw arrays from API but backend returns paginated `{items, total, page, perPage}`. Fixed for: useRepositories, useOrgs, useNotifications. May affect other hooks.
- **Fixed in:** commit `0d292ba`

### BUG-003: Database Migration Not Auto-Applied
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/db/migrations/`
- **Issue:** Migration 007_phase45_schema.py cannot run via `alembic upgrade head` because the alembic version table was out of sync. Columns applied manually via ALTER TABLE.
- **Fix needed:** Stamp alembic at 007 after manual columns applied, or fix migration to be idempotent.

### BUG-004: Scan Queue Endpoint Returns 500 (Sidebar Polling)
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/api/v1/scans.py`
- **Error:** `GET /api/v1/scans?status=running&page=1&perPage=1` returns 500
- **Impact:** Sidebar polls every 10s for running scan count. 50+ console errors per minute. Floods browser console.
- **Root cause:** Scan list_scans endpoint crashes on query param handling (perPage vs per_page, missing column handling)

### BUG-005: Auth Session Fragility
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `frontend/src/lib/auth.tsx`
- **Issue:** After login, navigating to several pages triggers 401 errors on API calls. Token may not be consistently attached to requests, or sidebar/layout hooks fire before token is available in sessionStorage.
- **Impact:** Pages load but API calls fail silently or return 401, causing empty data or crashes.

### BUG-006: Missing Backend Routes (404s)
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/api/v1/`
- **Missing routes:**
  - `GET /api/v1/admin/policy` — frontend calls this, backend has `/policy/effective` instead
  - `GET /api/v1/kanban` — migration board page, no backend route
  - `GET /api/v1/cbom/scans` — CBOM diff page, returns 404
- **Fix:** Either add routes or update frontend to match existing backend paths.

---

## LOW Priority

### BUG-007: Dashboard Data Gaps
- **Status:** OPEN
- **Severity:** LOW
- **Component:** `frontend/src/pages/PortfolioDashboard.tsx`
- **Issues:**
  - Quantum Readiness shows "%" without actual number
  - Compliance card shows "%" without actual number
  - Critical+High card shows "repos affected" without number
  - Groups in sidebar show as single letters (A, D, I, M, P, W) instead of full group names
- **Root cause:** Mock data or API response doesn't include these computed fields.

### BUG-008: Breadcrumbs Not Visible
- **Status:** OPEN
- **Severity:** LOW
- **Component:** `frontend/src/components/layout/Breadcrumbs.tsx`
- **Issue:** Breadcrumb component exists but not visible on dashboard or top-level pages. May only show on nested routes (repo detail pages).
- **Decision:** D22 #42 — breadcrumbs should show on all pages.

---

## UI Crawl Results (2026-03-28)

### Pages Tested: 20

| Page | URL | Status | Notes |
|---|---|---|---|
| Dashboard | / | OK | Loads with data, some empty cards |
| Projects | /repos | OK | "Repositories" heading, loads project list |
| Scans | /scans | OK | "Scan Queue" heading |
| Findings | /assets | TIMEOUT | Session-dependent, may load after login |
| Compliance | /compliance | TIMEOUT | Session-dependent |
| Compliance Dashboard | /compliance-dashboard | TIMEOUT | Session-dependent |
| Quantum Readiness | /quantum | TIMEOUT | Session-dependent |
| Certificates | /certificates | TIMEOUT | Session-dependent |
| Cert Tracker | /certificate-tracker | TIMEOUT | Session-dependent |
| CBOM Diff | /diff | TIMEOUT | `/cbom/scans` 404 |
| Migration Board | /migration | TIMEOUT | `/kanban` 404 |
| Org Settings | /admin/settings | TIMEOUT | Session-dependent |
| Users | /admin/users | TIMEOUT | Session-dependent |
| Integrations | /admin/integrations | TIMEOUT | Session-dependent |
| Audit Log | /admin/audit-log | TIMEOUT | Session-dependent |
| Registries | /admin/registries | TIMEOUT | Session-dependent |
| Pending Requests | /requests | TIMEOUT | Session-dependent |
| Policy Rules | /policy | TIMEOUT | `/admin/policy` 404 |
| Profile | /profile | TIMEOUT | Session-dependent |
| Forgot Password | /forgot-password | TIMEOUT | Public page, should work without auth |

**Note:** TIMEOUT results are from Playwright `page.goto()` which resets the browser session. In a real browser with persistent session, many of these pages likely work. Manual browser testing needed to confirm.

### Systematic D1-D32 Requirement Check

| Decision | Feature | UI Present | Backend Route | Working E2E | Notes |
|---|---|---|---|---|---|
| D1 | Scan modal (3 tabs) | YES — "+ New Scan" button | YES — POST /projects/{id}/scans/trigger | UNTESTED | Needs click test |
| D2 | Artifact registries | YES — /admin/registries | YES — CRUD routes | UNTESTED | 401 on page load |
| D3 | Integration connect | YES — /admin/integrations | YES — connect/test/repos | UNTESTED | |
| D4 | Customizable labels | PARTIAL — sidebar shows labels | YES — org settings | — | Groups show single letters |
| D5 | LLM config | YES — /admin/llm-config | YES — GET/PUT | UNTESTED | |
| D6 | Password management | YES — profile page | YES — PUT /auth/password | UNTESTED | |
| D7 | API keys | YES — profile page | YES — CRUD routes | UNTESTED | |
| D8 | Section 1 remaining | PARTIAL — SSO hidden, shortcuts modal exists | — | — | |
| D9 | User lifecycle | YES — user management | YES — role/disable/delete | UNTESTED | |
| D10 | User creation | YES — create modal | YES — invite/direct | UNTESTED | |
| D11 | Pagination | YES — component exists | YES — pagination_service | USED | On dashboard tables |
| D12 | Role resolution | YES — service exists | YES — get_effective_role | UNTESTED | |
| D13 | Finding table UX | YES — components exist | YES — sort/filter params | UNTESTED | |
| D14 | Finding status model | YES — status service | YES — PATCH /findings/{id}/status | UNTESTED | |
| D15 | FP/RA requests | YES — queue page, modal | YES — CRUD routes | UNTESTED | |
| D16 | Rule analytics | YES — enhanced policy page | YES — analytics endpoint | UNTESTED | |
| D17 | SE/TM role refinement | YES — RBAC in services | YES — middleware | UNTESTED | |
| D18 | Jira integration | YES — config + create issue | YES — routes | UNTESTED | |
| D19 | Bulk actions | YES — bulk action bar | YES — POST /findings/bulk | UNTESTED | |
| D20 | Scan management | YES — queue, schedule, progress | YES — WebSocket + routes | PARTIAL | Queue loads, progress untested |
| D21 | Scan provenance | YES — env badges, promote | YES — routes | UNTESTED | |
| D22 | Navigation overhaul | PARTIAL | — | — | Tabs consolidated, Lucide icons, search untested |
| D23 | Empty/placeholder pages | PARTIAL | YES — cert tracker, PQC | UNTESTED | |
| D24 | Onboarding | YES — wizard exists | — | UNTESTED | |
| D25 | Toast system | YES — component exists | — | USED | On dashboard |
| D26 | Policy cascade | YES — UI exists | YES — routes | UNTESTED | |
| D27 | Custom rules | YES — upload modal | YES — CRUD + delta sync | UNTESTED | |
| D28 | Audit log | YES — enhanced page | YES — filters + export | UNTESTED | |
| D29 | Theme fixes | PARTIAL — CSS updated | — | — | Crystal contrast, responsive untested |
| D30 | Login fixes | YES — forgot password link | YES — routes | UNTESTED | SSO buttons removed |
| D31 | Notification polish | PARTIAL | — | — | Webhook test button exists |
| D32 | Accessibility | PARTIAL — a11y components exist | — | — | Full audit needed |
| ADR-034 | Finding fingerprint | YES — CLI + backend | YES — matcher service | TESTED | 40 tests pass |
