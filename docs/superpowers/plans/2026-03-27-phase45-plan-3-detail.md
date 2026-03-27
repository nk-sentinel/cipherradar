# Phase 4.5 — Plan 3: Scan Lifecycle — Detailed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete scan lifecycle — modal, progress tracking, queue, scheduling, provenance, environment tagging, artifact registries.

**Architecture:** Backend services + WebSocket (FastAPI), frontend components (React 19), E2E tests (Playwright).

**Tech Stack:** FastAPI, SQLAlchemy 2.0 async, Redis Pub/Sub, WebSocket, Pydantic, pytest, Vitest, MSW, Playwright.

**Depends on (from Plans 1-2):**
- Models: `Scan` (with branch, commit_sha, environment, promoted_at), `ArtifactRegistry`, `EnvironmentStage` (all created)
- Columns: `Project.schedule_cron`, `Project.linked_sources`, `Organisation.stale_scan_threshold_days`
- Services: `pagination_service`, `audit_service`
- Schemas: `PaginatedResponse`, `PaginationParams`
- Frontend: `<Toast />`, `<Pagination />`
- WebSocket pattern: `backend/app/api/v1/ws.py` (Redis Pub/Sub → WebSocket)
- Existing scan routes: `backend/app/api/v1/scans.py` (create, get, list, findings)

---

## Agent Assignment

| Agent | Tasks | Notes |
|---|---|---|
| **Backend Scan** | 3.1, 3.4, 3.6, 3.8, 3.10, 3.12 | All backend services + routes |
| **Frontend Scan** | 3.2, 3.3, 3.5, 3.7, 3.9, 3.11, 3.13 | All frontend components + pages |
| **E2E + Perf** | 3.14, 3.15 | After backend + frontend complete |

Backend and Frontend agents run in parallel. E2E after both.

---

## Task 3.1: Backend — Scan Progress WebSocket (D20 #36)

**Files:**
- Create: `backend/app/services/scan_progress_service.py`
- Modify: `backend/app/api/v1/ws.py` (add scan progress WebSocket endpoint)
- Create: `backend/tests/services/test_scan_progress_service.py`

**Service:**
- `publish_progress(scan_id, status, detail, session)` — publishes to Redis channel `scan:{scan_id}`
- Status stages: `queued → cloning → scanning_pass1 → scanning_pass2 → generating_cbom → completed → failed`
- Each publish includes: `{scan_id, status, progress_pct, detail, timestamp}`

**WebSocket endpoint:** `/ws/scans/{scan_id}`
- Subscribes to Redis `scan:{scan_id}` channel
- Forwards progress events to connected clients
- Follow exact pattern from existing `/ws/notifications` endpoint

**Tests:**
- test_publish_progress_sends_to_redis
- test_progress_stages_valid
- test_progress_includes_percentage

Commit: `feat: add scan progress WebSocket and service (D20)`

---

## Task 3.2: Frontend — Scan Modal (D1)

**Files:**
- Create: `frontend/src/components/scan/ScanModal.tsx`
- Create: `frontend/src/components/scan/ScanSourceTabs.tsx`
- Create: `frontend/src/api/hooks/useTriggerScan.ts` (replace existing stub)
- Create: `frontend/tests/components/ScanModal.test.tsx`
- Modify: `frontend/src/mocks/handlers.ts` (update scan trigger handler)

**ScanModal:**
- 3 tabs: Repository, Container Image, Artifact
- Repository tab: branch selector (from project's git config), policy selector
- Container tab: tag selector (from project's linked container source)
- Artifact tab: version selector or upload
- Context-aware:
  - Dashboard "+ New Scan": full 3-tab modal, project selector first
  - Repo row "Scan": pre-fills project, source tab
  - RepoOverview "Scan Now": simplified (branch + policy), "More options" expands
- Submit calls `POST /api/v1/projects/{projectId}/scans/trigger`
- Locked targets: user picks branch/tag/version only, not URL (D1 data poisoning prevention)

**Tests:**
- test_modal_renders_three_tabs
- test_repo_tab_shows_branch_selector
- test_context_aware_prefill_from_project
- test_submit_triggers_scan_api
- test_upload_tab_shows_file_input

Commit: `feat: add scan modal with 3 source types (D1)`

---

## Task 3.3: Frontend — Scan Progress UI (D20 #36)

**Files:**
- Create: `frontend/src/components/scan/ScanProgressBar.tsx`
- Create: `frontend/src/lib/use-scan-progress.ts` (WebSocket hook)
- Create: `frontend/tests/components/ScanProgressBar.test.tsx`
- Modify: `frontend/src/pages/repo/RepoOverview.tsx` (add progress bar)

**ScanProgressBar:**
- Animated progress bar with stage labels
- Stages: Queued → Cloning → Scanning → Generating CBOM → Complete
- Color: cyan while running, green on complete, red on failed
- Toast notification on completion/failure

**WebSocket hook:**
- Connects to `ws://localhost:8001/ws/scans/{scanId}`
- Returns: `{ status, progressPct, detail, isComplete, isError }`
- Auto-disconnects on complete/unmount

**Tests:**
- test_progress_bar_shows_current_stage
- test_progress_bar_completes_green
- test_progress_bar_fails_red

Commit: `feat: add scan progress UI with WebSocket (D20)`

---

## Task 3.4: Backend — Scan Queue API (D20 #38)

**Files:**
- Modify: `backend/app/api/v1/scans.py` (enhance existing list_scans)
- Create: `backend/app/schemas/scan_queue.py`
- Create: `backend/tests/api/test_scan_queue.py`

**Enhance existing `GET /api/v1/scans`:**
- Add query params: `status`, `project_id`, `trigger_type` (manual/scheduled/webhook/push)
- Add pagination via `pagination_service`
- RBAC-scoped per D12: users see scans for groups they can access
- Response includes: project name, trigger type, triggered_by user, duration

**Tests:**
- test_scan_queue_paginated
- test_scan_queue_filter_by_status
- test_scan_queue_filter_by_project
- test_scan_queue_rbac_scoped

Commit: `feat: enhance scan queue with filters and pagination (D20)`

---

## Task 3.5: Frontend — Scan Queue Page (D20 #38)

**Files:**
- Create: `frontend/src/pages/ScanQueue.tsx`
- Create: `frontend/src/api/hooks/useScanQueue.ts`
- Create: `frontend/tests/pages/ScanQueue.test.tsx`
- Modify: `frontend/src/router.tsx` (add /scans route)
- Modify: `frontend/src/components/layout/Sidebar.tsx` (add "Scans" nav item with count)

**ScanQueue page:**
- Table: project name, trigger type, status badge, started, duration, triggered by
- Filters: status dropdown, project dropdown, trigger type dropdown
- Pagination
- Auto-refresh every 10s for running scans

**Tests:**
- test_scan_queue_renders_table
- test_scan_queue_filters
- test_scan_queue_pagination

Commit: `feat: add scan queue page (D20)`

---

## Task 3.6: Backend — Scan Scheduling (D20 #39)

**Files:**
- Create: `backend/app/services/scan_schedule_service.py`
- Create: `backend/app/schemas/scan_schedule.py`
- Create: `backend/app/api/v1/scan_schedule.py`
- Create: `backend/tests/services/test_scan_schedule_service.py`

**Service:**
- `get_schedule(project_id?, group_id?, session)` — return effective schedule (project → group → org)
- `save_schedule(scope_type, scope_id, cron, timezone, session)` — save schedule
- `resolve_schedule(project_id, session)` — cascade resolution: project → group → org → none
- Validates: org `allow_project_schedule_override` setting

**Routes:**
- `GET /api/v1/projects/{project_id}/schedule`
- `PUT /api/v1/projects/{project_id}/schedule` — Roles: OA, SM, SE
- `GET /api/v1/groups/{group_id}/schedule`
- `PUT /api/v1/groups/{group_id}/schedule` — Roles: OA, SM

**Schemas:**
```python
class ScheduleResponse(CamelCaseModel):
    cron: str | None
    timezone: str
    source: str  # "project", "group", "org", "none"
    next_run: datetime | None

class ScheduleUpdate(CamelCaseModel):
    preset: str | None  # "daily", "weekly", None (custom)
    cron: str | None  # only if preset is None
    timezone: str = "UTC"
```

**Tests:**
- test_resolve_schedule_project_overrides_group
- test_resolve_schedule_falls_back_to_org
- test_save_schedule_respects_override_setting
- test_daily_preset_converts_to_cron
- test_weekly_preset_converts_to_cron

Commit: `feat: add scan scheduling with three-tier cascade (D20)`

---

## Task 3.7: Frontend — Schedule Config UI (D20 #39)

**Files:**
- Create: `frontend/src/components/scan/ScheduleConfig.tsx`
- Create: `frontend/src/api/hooks/useSchedule.ts`
- Create: `frontend/tests/components/ScheduleConfig.test.tsx`

**ScheduleConfig (reusable for project/group/org settings):**
- Preset selector: Off / Daily / Weekly
- Time picker (hour) + timezone dropdown
- Shows effective schedule source: "Inherited from group: Daily at 2:00 UTC"
- Override indicator when project differs from group/org
- Save button

**Tests:**
- test_preset_selector_daily_weekly
- test_shows_inherited_source
- test_save_calls_api

Commit: `feat: add scan schedule config UI (D20)`

---

## Task 3.8: Backend — Scan Provenance & Promotion (D21)

**Files:**
- Create: `backend/app/services/scan_provenance_service.py`
- Create: `backend/app/schemas/scan_provenance.py`
- Create: `backend/app/api/v1/scan_provenance.py`
- Create: `backend/tests/services/test_scan_provenance_service.py`

**Service:**
- `get_provenance(scan_id, session)` — return provenance fields (branch, SHA, digest, env)
- `promote(scan_id, from_env, to_env, actor, session)` — transfer environment tag, demote old prod scan, audit log
- `get_environments(org_id, session)` — list configured stages
- `save_environments(org_id, stages, session)` — save stage config

**Routes:**
- `GET /api/v1/scans/{scan_id}/provenance`
- `POST /api/v1/scans/promote` — Roles: OA, SM, SE
- `GET /api/v1/admin/environments`
- `PUT /api/v1/admin/environments` — Roles: OA

**Promotion logic:**
- Find scan by ID, verify from_env matches current
- Set new environment, promoted_at, promoted_by
- Find any other scan for same project with to_env tag → remove its env tag (one active per env per project)
- Audit log: `scan.promote`

**Tests:**
- test_promote_transfers_environment_tag
- test_promote_demotes_previous_prod_scan
- test_promote_requires_se_or_above
- test_provenance_returns_all_fields
- test_environment_stages_crud

Commit: `feat: add scan provenance and environment promotion (D21)`

---

## Task 3.9: Frontend — Environment Tags & Promotion UI (D21)

**Files:**
- Create: `frontend/src/components/scan/EnvironmentBadge.tsx`
- Create: `frontend/src/components/scan/PromoteModal.tsx`
- Create: `frontend/src/api/hooks/useProvenance.ts`
- Create: `frontend/tests/components/PromoteModal.test.tsx`
- Modify: `frontend/src/pages/repo/ScanHistoryPage.tsx` (add env badges + promote button)

**EnvironmentBadge:** Colored badge per env stage (dev=gray, staging=amber, production=green)

**PromoteModal:**
- "Promote to..." dropdown showing available next stages
- Confirmation: "Promote scan abc123 from Staging to Production?"
- Submit calls `POST /api/v1/scans/promote`
- Toast on success

**Tests:**
- test_environment_badge_renders_variants
- test_promote_modal_shows_available_stages
- test_promote_submits_correctly

Commit: `feat: add environment tags and promotion UI (D21)`

---

## Task 3.10: Backend — Stale Warning + Rerun (D20 #37, #40)

**Files:**
- Modify: `backend/app/api/v1/scans.py` (add rerun endpoint)
- Create: `backend/app/schemas/scan_rerun.py`
- Create: `backend/tests/api/test_scan_rerun.py`

**Rerun:** `POST /api/v1/scans/{scan_id}/rerun` — clones scan config (branch, policy, source type), creates new scan. Roles: OA, SM, SE.

**Stale check:** Add `is_stale` computed field to project response when `last_scan_at > org.stale_scan_threshold_days`.

**Tests:**
- test_rerun_creates_new_scan_with_same_config
- test_rerun_rbac
- test_stale_indicator_on_project

Commit: `feat: add scan rerun and stale scan detection (D20)`

---

## Task 3.11: Frontend — Stale Warning & Rerun UI

**Files:**
- Create: `frontend/src/components/scan/StaleScanBanner.tsx`
- Create: `frontend/tests/components/StaleScanBanner.test.tsx`
- Modify: `frontend/src/pages/repo/RepoOverview.tsx` (add stale banner + rerun button on scan rows)
- Modify: `frontend/src/pages/repo/ScanHistoryPage.tsx` (add rerun button)

**StaleScanBanner:** Amber banner: "Last scan was N days ago. Run a new scan?" with action button.

**Tests:**
- test_stale_banner_shows_when_overdue
- test_stale_banner_hidden_when_recent
- test_rerun_button_calls_api

Commit: `feat: add stale scan warning and rerun UI (D20)`

---

## Task 3.12: Backend — Artifact Registry CRUD (D2)

**Files:**
- Create: `backend/app/services/artifact_registry_service.py`
- Create: `backend/app/schemas/artifact_registry.py`
- Create: `backend/app/api/v1/artifact_registries.py`
- Create: `backend/tests/services/test_artifact_registry_service.py`
- Create: `backend/tests/api/test_artifact_registries.py`

**Routes:**
- `GET /api/v1/admin/registries` — Roles: OA, SM
- `POST /api/v1/admin/registries` — Roles: OA
- `PUT /api/v1/admin/registries/{id}` — Roles: OA
- `DELETE /api/v1/admin/registries/{id}` — Roles: OA
- `POST /api/v1/admin/registries/{id}/test` — Roles: OA

**Service:** CRUD + test connection (mock for Phase 4.5, real in Plan 5 when integration tokens are wired).

**Tests:**
- test_create_registry
- test_list_registries
- test_update_registry
- test_delete_registry
- test_test_connection
- test_rbac_sm_cannot_create

Commit: `feat: add artifact registry CRUD (D2)`

---

## Task 3.13: Frontend — Artifact Registry Admin Page (D2)

**Files:**
- Create: `frontend/src/pages/admin/ArtifactRegistries.tsx`
- Create: `frontend/src/api/hooks/useRegistries.ts`
- Create: `frontend/tests/pages/ArtifactRegistries.test.tsx`
- Modify: `frontend/src/router.tsx` (add admin route)
- Modify: `frontend/src/mocks/handlers.ts` (add registry handlers)

**Page:**
- Table: name, type, URL, status (connected/disconnected), last tested
- Add registry modal: name, type dropdown (JFrog/ECR/GCR/ACR/Docker Hub/Harbor/GitLab/Custom), URL, auth method, credentials
- Test connection button per row
- Edit/delete actions (OA only)

**Tests:**
- test_registry_table_renders
- test_add_registry_modal
- test_test_connection_button

Commit: `feat: add artifact registry admin page (D2)`

---

## Task 3.14: E2E — Scan Lifecycle Tests

**Files:**
- Create: `frontend/e2e/scan-lifecycle.spec.ts`

**Scenarios:**
1. Admin triggers scan from modal → sees progress → scan completes
2. Navigate to scan queue → verify running scan visible
3. Promote scan to production → verify environment badge
4. Stale scan warning shows on old project
5. Accessibility scan on scan queue page

Commit: `test: add scan lifecycle E2E tests`

---

## Task 3.15: Performance — Scan Endpoints

**Modify:** `backend/tests/performance/locustfile.py`

Add tasks for: scan queue, schedule, provenance, registries.

Commit: `perf: add scan lifecycle load tests`

---

## Completion Criteria

- [ ] Scan modal with 3 source types works (D1)
- [ ] WebSocket scan progress updates in real-time (D20)
- [ ] Scan queue page with filters and pagination (D20)
- [ ] Three-tier scheduling works (project → group → org) (D20)
- [ ] Scan provenance captured + environment promotion works (D21)
- [ ] Stale scan warning + rerun button work (D20)
- [ ] Artifact registry CRUD with test connection (D2)
- [ ] E2E tests pass
- [ ] All pages pass axe-core WCAG 2.1 AA
