# Phase 4.5 — Post-Implementation Bug Tracker

> **Created:** 2026-03-28
> **Last updated:** 2026-04-16
> **Status:** Active — most HIGH/MEDIUM bugs resolved; remaining items tracked below

---

## HIGH Priority

### BUG-001: Scanner Worker Crash Loop
- **Status:** RESOLVED (2026-04-10)
- **Severity:** HIGH
- **Component:** `backend/app/workers/scan_worker.py`
- **Error:** `NameError: name 'uuid' is not defined` during Taskiq broker import; previously misreported as `AttributeError: ... no attribute 'broker'`
- **Impact:** Scanner worker container restarted in a loop. No scans could be triggered.
- **Root cause:** `import uuid` was placed under a `if TYPE_CHECKING:` guard so it wasn't imported at runtime. Taskiq evaluates type hints via `get_type_hints()` on every `@broker.task` decoration, which requires `uuid` to be importable at module load time.
- **Fix:** Moved `import uuid` to a top-level import in `backend/app/workers/scan_worker.py`. Worker now starts cleanly and 2 listeners spin up as expected.
- **Pre-existing:** Yes — not introduced by Phase 4.5 changes.

### BUG-013: JWT fingerprint breaks behind reverse proxies
- **Status:** RESOLVED (2026-04-15)
- **Severity:** HIGH
- **Component:** `backend/app/auth/middleware.py`, `backend/app/api/v1/auth.py`, `frontend/nginx.conf`
- **Issue:** JWT embeds `SHA256(user_agent + client_ip + secret)` fingerprint. Behind a proxy chain (Traefik → frontend nginx → API), `request.client.host` returns the nginx container IP, which can change on container restart, invalidating all live tokens.
- **Impact:** Intermittent 401s on all authenticated API calls, especially after any container restart.
- **Fix:** Three-part:
  1. `frontend/nginx.conf` now sets `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host` on `/api/` proxy
  2. Backend reads `X-Forwarded-For` first, falls back to `request.client.host`. Applied at fingerprint *create* time (login + refresh) and *verify* time (middleware) so they always use the same source.
  3. New `CRADAR_FINGERPRINT_ENABLED` setting (default `True`) lets dev/homelab disable fingerprinting where the IP varies. Set to `false` in `deploy/docker-compose.homelab.yml`.

---

## MEDIUM Priority

### BUG-002: Frontend API Response Shape Mismatches
- **Status:** RESOLVED (2026-04-15) — was PARTIALLY FIXED in `0d292ba`
- **Severity:** MEDIUM
- **Component:** `frontend/src/api/hooks/`, `backend/app/api/v1/portfolio.py`, `backend/app/services/portfolio_service.py`
- **Issue:** Multiple hooks expect raw arrays from API but backend returns paginated `{items, total, page, perPage}`. Portfolio dashboard expected ~12 fields but API returned 3. Heatmap returned group-level data; frontend expected repo-level with all 5 severity levels.
- **Fix:**
  1. `useRepositories`, `useOrgs`, `useNotifications` paginated-response handling (commit `0d292ba`)
  2. `PortfolioSummary` schema and service expanded to compute and return `criticalPlusHigh`, `affectedRepos`, `quantumExposed`, `quantumExposedPercent`, `complianceAvg`, `complianceFramework`, `lastScanTime`, `severityDistribution`. Renamed `quantumReadinessPct` → `quantumReadinessPercent` to match frontend.
  3. `TopRepo` adds `provider`, `quantumRisk`, `compliancePercent`, `lastScan`
  4. `/portfolio/heatmap` rewritten to return repo-level data with all 5 severities
  5. `useHeatMap` hook normalizes `projectId`/`projectName` → `repoId`/`repoName`

### BUG-003: Database Migration Not Auto-Applied
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/db/migrations/`
- **Issue:** Migration `007_phase45_schema.py` cannot run via `alembic upgrade head` because the alembic version table was out of sync. Columns applied manually via ALTER TABLE.
- **Fix needed:** Stamp alembic at 007 after manual columns applied, or fix migration to be idempotent.

### BUG-004: Scan Queue Endpoint Returns 500 (Sidebar Polling)
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/api/v1/scans.py`
- **Error:** `GET /api/v1/scans?status=running&page=1&perPage=1` returns 500
- **Impact:** Sidebar polls every 10s for running scan count. 50+ console errors per minute; floods browser console.
- **Root cause:** Scan list_scans endpoint crashes on query param handling (perPage vs per_page, missing column handling). May also be hitting BUG-012 (`uuid.UUID(user.org_id)` raises ValueError).

### BUG-005: Auth Session Fragility
- **Status:** RESOLVED (2026-04-15)
- **Severity:** MEDIUM
- **Component:** `frontend/src/lib/auth.tsx`, `frontend/src/App.tsx`, `frontend/src/api/client.ts`
- **Issue:** After login, navigating to several pages triggered 401 errors. Pages loaded but API calls failed silently or returned 401, causing empty data or "Welcome to CipherRadar" onboarding screens for authenticated users.
- **Root cause:** Two compounding issues:
  1. Race condition — `memoryToken` module variable was set as a side effect inside one `useState` initializer, but a second `useState` read it during the same render. React doesn't guarantee initializer order with side effects, leaving `token = null` despite valid sessionStorage.
  2. No global handling of 401 responses — when a query failed, the user saw a half-loaded broken page instead of being redirected to login.
- **Fix:**
  1. `auth.tsx` — replaced `memoryToken` + two `useState` with a single `restoreSession()` function returning `{token, user}` atomically, used by a single `useState` call. SessionStorage writes now happen *before* state updates so the two never disagree.
  2. `App.tsx` — added `QueryCache.onError` global handler that detects `ApiError` with status 401, clears sessionStorage, and redirects to `/login?expired=1` if not already there. Disabled retry on 401 errors via custom `retry` function.
  3. Together with BUG-013 fix, sessions are now stable and broken sessions land cleanly on the login page instead of broken UI.

### BUG-006: Missing Backend Routes (404s)
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `backend/app/api/v1/`
- **Missing routes:**
  - `GET /api/v1/admin/policy` — frontend calls this, backend has `/policy/effective` instead
  - `GET /api/v1/kanban` — migration board page, no backend route
  - `GET /api/v1/cbom/scans` — CBOM diff page, returns 404
- **Fix:** Either add routes or update frontend to match existing backend paths.

### BUG-011: Group selector lists organizations in import modal
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** `frontend/src/pages/admin/IntegrationManagement.tsx:398`
- **Issue:** When importing repositories from a Git provider, the dropdown intended to assign repos to a Group instead lists Organizations (uses `useUserOrgs()` hook).
- **Impact:** Imported projects can't be assigned to a Group through this flow; users may select wrong destination.
- **Fix needed:** Replace `useUserOrgs()` with `useGroups()`; rebind selected value to `groupId` field on import payload.

### BUG-012: Bare `uuid.UUID(user.org_id)` causes 500s on bad sessions
- **Status:** OPEN
- **Severity:** MEDIUM
- **Component:** Backend, ~14 files / ~50 call sites
- **Issue:** When a JWT carries a malformed or empty `org_id` (e.g. stale token from before an org migration), endpoints calling `uuid.UUID(user.org_id)` raise `ValueError: badly formed hexadecimal UUID string` and return 500 with a stack trace instead of a clean 401/403.
- **Affected files:** `api/v1/admin.py`, `api/v1/projects.py`, `api/v1/scans.py`, `api/v1/jira.py`, `api/v1/finding_requests.py`, `api/v1/scan_schedule.py`, `api/v1/scan_provenance.py`, `api/v1/rule_analytics.py`, `api/v1/graph.py`, `api/v1/artifact_registries.py`, plus services: `finding_status_service.py`, `custom_rule_service.py`, `scan_provenance_service.py`, `llm_config_service.py`, `integration_service.py`, `group_service.py`, `finding_request_service.py`
- **Fix needed (Fix B blueprint):**
  1. Add `org_uuid: uuid.UUID | None` and `user_uuid: uuid.UUID` attributes on `AuthenticatedUser` (`backend/app/auth/middleware.py`)
  2. Parse and validate in `__init__`; mark invalid as None
  3. In `get_current_user()`, raise 401 if `user_uuid is None`
  4. Add `required_org_uuid` property that raises 403 when missing
  5. Replace all 50 call sites with `user.required_org_uuid` / `user.user_uuid`
- **Workaround:** Logout / re-login to get a fresh JWT.

### BUG-014: Seed script crash on `trigger_type` column
- **Status:** RESOLVED (2026-04-10)
- **Severity:** MEDIUM
- **Component:** `backend/scripts/seed.py`
- **Issue:** Seed script INSERTed into `scans` table referencing `trigger_type` and `triggered_by` columns that don't exist on the `scans` model/table.
- **Impact:** Seed script aborted partway, leaving DB in inconsistent state and blocking demo data setup.
- **Fix:** Removed `trigger_type` and `triggered_by` columns from the INSERT in `seed.py:689`. The scan model only has the canonical columns from migration 001.

### BUG-015: `GET /api/v1/projects/{id}` endpoint missing
- **Status:** RESOLVED (2026-04-13)
- **Severity:** MEDIUM
- **Component:** `backend/app/api/v1/projects.py`
- **Issue:** Frontend `useRepository(repoId)` hook called `GET /api/v1/projects/{id}` to resolve project name for breadcrumbs, but only `GET /api/v1/projects` (list) existed. Single fetch returned 404, leaving breadcrumbs to show raw UUIDs.
- **Fix:** Added `GET /api/v1/projects/{project_id}` that returns the existing `ProjectResponse` shape extended with `groupName` and `orgPath` fields. Both list and single endpoints prefetch group names so the frontend gets full hierarchy in one call.

---

## LOW Priority

### BUG-007: Dashboard Data Gaps
- **Status:** RESOLVED (2026-04-15) — fully addressed alongside BUG-002
- **Severity:** LOW
- **Component:** `frontend/src/pages/PortfolioDashboard.tsx`, `backend/app/services/portfolio_service.py`
- **Issues that were present:**
  - Quantum Readiness showed "%" without actual number
  - Compliance card showed "%" without actual number
  - Critical+High card showed "repos affected" without number
  - Groups in sidebar showed as single letters (A, D, I, M, P, W) instead of full group names
- **Root cause:** `PortfolioSummary` API response was missing 8+ computed fields the frontend expected; `/projects` endpoint didn't return `groupName`.
- **Fix:** See BUG-002. Group sidebar now uses `groupName` from the project endpoint instead of the first letter of the ID.

### BUG-008: Breadcrumbs Not Visible / Accumulating
- **Status:** RESOLVED (2026-04-16)
- **Severity:** LOW (visibility) → HIGH (accumulation, discovered later)
- **Component:** `frontend/src/components/layout/Breadcrumbs.tsx`, `frontend/src/pages/repo/RepoLayout.tsx`, `frontend/src/pages/repo/ScanDetailPage.tsx`
- **Issues:**
  1. (Original) Breadcrumb component existed but only showed on nested routes
  2. (Discovered during fix) Navigating between projects accumulated old project UUIDs in the breadcrumb instead of replacing them
- **Root cause of accumulation:** The breadcrumb spans used `segment.to` as React key. The project link and the "Overview" tab segment both produced `to: '/repos/{id}/overview'` — duplicate keys broke React reconciliation, leaving stale spans from previous routes in the DOM.
- **Fix:**
  1. Removed duplicate `<div className="breadcrumb">` from `RepoLayout.tsx` and `ScanDetailPage.tsx` (TopBar `<Breadcrumbs />` is the single source)
  2. Added `key={pathname}` on the `<nav>` element to force full re-mount on every route change
  3. Changed span key from `segment.to` to `${index}-${segment.to}` to guarantee uniqueness
  4. `buildBreadcrumbs` now handles 5 levels including `/repos/{id}/scans/{scanId}` sub-pages
  5. `useHeatMap` normalizes API `projectId`/`projectName` → `repoId`/`repoName` so heatmap clicks navigate correctly

### BUG-009: Manual project creation missing (non-Git)
- **Status:** OPEN
- **Severity:** LOW
- **Component:** `frontend/src/pages/admin/IntegrationManagement.tsx:602`
- **Issue:** "+ New Project" button on the Integrations page shows a "Coming soon" placeholder. There is no way to create a project for a vendor / non-Git source through the UI. No `POST /api/v1/projects` endpoint exists either.
- **Workaround:** Use the CLI: `cradar scan /path --push`
- **Reference:** `docs/PHASE-4.5-UI-AUDIT-REPORT.md:122` (H19)

### BUG-010: Organization creation UI missing
- **Status:** OPEN
- **Severity:** LOW
- **Component:** `frontend/src/pages/admin/`, `backend/app/api/v1/`
- **Issue:** No UI exists for an org_admin to create a new organisation. Organisations are created only during user signup / onboarding. There is no admin endpoint to create orgs either.
- **Impact:** Multi-org tenants can't self-serve org creation. Workaround is direct DB insert or running the signup flow.

### BUG-016: Stale JWT after org/role changes shows broken pages
- **Status:** RESOLVED operationally (2026-04-16) — covered by BUG-005 fix
- **Severity:** LOW
- **Component:** Operational / `frontend/src/App.tsx`
- **Issue:** When an admin user is moved between orgs or has their role changed via direct DB update, in-flight JWTs continue to claim the old org/role. Resulting 401/403 responses previously left the user on a half-loaded page.
- **Fix:** With BUG-005 deployed, any 401 from any query now redirects to `/login?expired=1`. Operational note: anytime user/org assignments are changed via DB, instruct affected users to logout and re-login.

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
