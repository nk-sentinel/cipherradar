# Phase 4.5 — Plan 2: Finding Workflow — Detailed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete finding lifecycle — status model, FP/RA requests, assignments, bulk actions, Jira integration, rule analytics, code highlighting.

**Architecture:** Backend services + routes (FastAPI), frontend pages + components (React 19), E2E tests (Playwright). All endpoints follow the API contract in `docs/api-contracts/phase45-endpoints.yaml`.

**Tech Stack:** FastAPI, SQLAlchemy 2.0 async, Pydantic, pytest, Vitest, React Testing Library, MSW, Playwright, axe-core.

**Depends on (from Plan 1):**
- Models: `Finding`, `FindingStatusHistory`, `FindingRequest`, `FindingComment`, `JiraConfig` (all created)
- Services: `finding_matcher`, `pagination_service`, `audit_service` (all created)
- Schemas: `PaginatedResponse`, `PaginationParams` (created)
- Frontend: `<Toast />`, `<Pagination />` components (created)
- Factories: `FindingFactory`, `UserFactory`, `ProjectFactory` (created)

---

## Agent Assignment

| Agent | Tasks | Parallel group |
|---|---|---|
| **Backend Finding** | 2.1, 2.3, 2.5, 2.7 | A (backend services + routes) |
| **Backend Jira+Analytics** | 2.9, 2.11 | A (can run alongside Finding agent) |
| **Frontend Finding** | 2.2, 2.4, 2.6, 2.8, 2.13 | B (frontend components + pages) |
| **Frontend Jira+Analytics** | 2.10, 2.12 | B (can run alongside Finding frontend) |
| **E2E + Review** | 2.14, 2.15 | C (after A + B complete) |

```
Group A (backend):  [2.1 → 2.3 → 2.5 → 2.7]  +  [2.9 → 2.11]
Group B (frontend): [2.2 → 2.4 → 2.6 → 2.8 → 2.13]  +  [2.10 → 2.12]
Group C (test):     [2.14 + 2.15] — after A & B
```

---

## Task 2.1: Backend — Finding Status Service (D14)

**Files:**
- Create: `backend/app/services/finding_status_service.py`
- Create: `backend/app/schemas/finding_status.py`
- Create: `backend/app/api/v1/finding_status.py`
- Create: `backend/tests/services/test_finding_status_service.py`
- Create: `backend/tests/api/test_finding_status.py`
- Modify: `backend/app/api/v1/__init__.py` (register router)
- Modify: `docs/RBAC-REFERENCE.md` (add finding status endpoints)

**Schemas (`finding_status.py`):**
```python
class FindingStatusUpdate(CamelCaseModel):
    status: str  # open, in_review, in_progress, resolved, risk_accepted, false_positive
    reason: str | None = None
    reason_category: str | None = None  # compensating_control, low_impact, migration_planned, business_exception
    review_date: date | None = None

class FindingStatusHistoryItem(CamelCaseModel):
    id: uuid.UUID
    old_status: str | None
    new_status: str
    changed_by: uuid.UUID | None
    reason: str | None
    created_at: datetime
    model_config = {**CamelCaseModel.model_config, "from_attributes": True}

class FindingAssignment(CamelCaseModel):
    assignee_id: uuid.UUID
```

**Service (`finding_status_service.py`):**
- `change_status(finding_id, new_status, actor, reason, session)` — validates transition, enforces RBAC per D14/D17, records history, logs audit
- `get_history(finding_id, session)` → list of status transitions
- `assign(finding_id, assignee_id, actor, session)` — validates scope (D17), auto-transitions to In Review if Open
- Valid transitions: Open→any, In Review→Open/In Progress/Resolved/FP/RA, In Progress→Open/In Review/Resolved, Resolved→Open(reopen), RA/FP→Open(reversal with reason)
- RA/FP require mandatory justification
- RA requires SM/OA role. FP requires SM/OA for direct, SE+ for request approval.

**Routes (`finding_status.py`):**
- `PATCH /api/v1/findings/{finding_id}/status`
- `GET /api/v1/findings/{finding_id}/history`
- `PATCH /api/v1/findings/{finding_id}/assign`

**RBAC per D17:**

| Action | OA | SM | SE | TM | DEV | CA | Guest |
|---|---|---|---|---|---|---|---|
| Change to Open/In Review/In Progress | x | x | x | x | x(own) | | |
| Change to Resolved | x | x | x | | | | |
| Change to Risk Accepted | x | x | | | | | |
| Change to False Positive | x | x | | | | | |
| Assign | x | x | x(group) | x(group) | self-only | | |
| View history | x | x | x | x | x | x | |

- [ ] Write test: `test_change_status_open_to_in_review`
- [ ] Write test: `test_change_status_requires_reason_for_ra`
- [ ] Write test: `test_change_status_requires_reason_for_fp`
- [ ] Write test: `test_invalid_transition_rejected`
- [ ] Write test: `test_rbac_dev_cannot_mark_fp`
- [ ] Write test: `test_rbac_only_sm_oa_can_mark_ra`
- [ ] Write test: `test_status_history_recorded`
- [ ] Write test: `test_audit_log_on_status_change`
- [ ] Write test: `test_assign_auto_transitions_to_in_review`
- [ ] Write test: `test_assign_respects_group_scope`
- [ ] Write test: `test_dev_self_assign_only`
- [ ] Implement service
- [ ] Implement routes
- [ ] Run tests: `.venv/bin/python -m pytest tests/services/test_finding_status_service.py tests/api/test_finding_status.py -v`
- [ ] Update MSW handlers: `frontend/src/mocks/handlers.ts`
- [ ] Update RBAC-REFERENCE.md
- [ ] Commit: `feat: add finding status service and routes (D14, D17)`

---

## Task 2.2: Frontend — Finding Table UX (D13)

**Files:**
- Modify: `frontend/src/pages/repo/RepoFindings.tsx` (or `RepoFindingsPage.tsx`)
- Create: `frontend/src/components/findings/FindingStatusBadge.tsx`
- Create: `frontend/src/components/findings/FindingStatusFilter.tsx`
- Create: `frontend/src/components/findings/DetectionBadge.tsx`
- Modify: `frontend/src/api/hooks/useFindings.ts` (add sort, pagination params)
- Create: `frontend/tests/components/FindingStatusFilter.test.tsx`
- Create: `frontend/tests/components/FindingStatusBadge.test.tsx`
- Modify: `frontend/src/mocks/handlers.ts` (update findings handler with status filter)

**Requirements:**
- Sortable columns: severity, file, algorithm, first seen, status, confidence, detection
- Default sort: severity desc, then first-seen desc
- Server-side pagination using `<Pagination />` from Plan 1
- Status filter bar: `[All] [Open (147)] [In Review (23)] [In Progress (31)] [Resolved (412)] [Risk Accepted (18)] [FP (9)]`
- Default: Open + In Review + In Progress selected
- "Detection" column replacing "Pass" (Pattern = Pass 1, Taint = Pass 2)
- File-grouped view toggle

- [ ] Write test: `test_status_filter_bar_renders_with_counts`
- [ ] Write test: `test_status_badge_renders_correct_variant`
- [ ] Write test: `test_detection_badge_shows_pattern_or_taint`
- [ ] Write test: `test_sort_toggles_asc_desc`
- [ ] Implement FindingStatusBadge, FindingStatusFilter, DetectionBadge
- [ ] Update RepoFindings page with new components + pagination
- [ ] Update useFindings hook with sort/filter/pagination params
- [ ] Update MSW mock data to include status field
- [ ] Run tests: `npx vitest run tests/components/FindingStatus*.test.tsx`
- [ ] Commit: `feat: add finding table UX — sorting, pagination, status filter (D13)`

---

## Task 2.3: Backend — FP/RA Request Workflow (D15)

**Files:**
- Create: `backend/app/services/finding_request_service.py`
- Create: `backend/app/schemas/finding_request.py`
- Create: `backend/app/api/v1/finding_requests.py`
- Create: `backend/tests/services/test_finding_request_service.py`
- Create: `backend/tests/api/test_finding_requests.py`
- Modify: `backend/app/api/v1/__init__.py`
- Modify: `docs/RBAC-REFERENCE.md`

**Service:**
- `create_request(finding_id, request_type, justification, actor, session)` — validates RBAC, creates FindingRequest
- `list_requests(org_id, actor_role, page, per_page, session)` — paginated, RBAC-scoped
- `approve(request_id, actor, session)` — changes finding status, records history
- `reject(request_id, reason, actor, session)` — closes request, finding stays as-is

**Routes:**
- `POST /api/v1/findings/{finding_id}/request`
- `GET /api/v1/requests`
- `POST /api/v1/requests/{request_id}/approve`
- `POST /api/v1/requests/{request_id}/reject`

**RBAC per D15:**

| Action | OA | SM | SE | TM | DEV |
|---|---|---|---|---|---|
| Raise FP/RA request | | | x | x | x |
| Approve FP | x | x | x* | | |
| Approve RA | x | x | | | |
| Reject | x | x | x* | | |
| View queue | x | x | x | x** | |

*SE cannot approve own requests
**TM sees only own group's requests

- [ ] Write test: `test_dev_can_raise_fp_request`
- [ ] Write test: `test_sm_can_approve_ra_request`
- [ ] Write test: `test_se_cannot_approve_own_fp_request`
- [ ] Write test: `test_approve_changes_finding_status`
- [ ] Write test: `test_reject_keeps_finding_status`
- [ ] Write test: `test_soft_rate_limit_warning`
- [ ] Write test: `test_request_list_rbac_scoped`
- [ ] Implement service + routes
- [ ] Update MSW handlers
- [ ] Update RBAC-REFERENCE.md
- [ ] Commit: `feat: add FP/RA request workflow (D15)`

---

## Task 2.4: Frontend — FP/RA Request UI (D15)

**Files:**
- Create: `frontend/src/components/findings/RequestModal.tsx`
- Create: `frontend/src/pages/RequestQueue.tsx`
- Create: `frontend/src/api/hooks/useRequests.ts`
- Modify: `frontend/src/router.tsx` (add /requests route)
- Modify: `frontend/src/components/layout/Sidebar.tsx` (add Pending Requests with badge)
- Create: `frontend/tests/components/RequestModal.test.tsx`
- Create: `frontend/tests/pages/RequestQueue.test.tsx`

- [ ] Write tests for RequestModal (form validation, submit, consent)
- [ ] Write tests for RequestQueue page (list, approve, reject actions)
- [ ] Implement RequestModal with justification form
- [ ] Implement RequestQueue page with table + actions
- [ ] Add useRequests hook (list, approve, reject mutations)
- [ ] Add route + sidebar entry with count badge
- [ ] Update MSW handlers
- [ ] Run tests
- [ ] Commit: `feat: add FP/RA request UI and queue page (D15)`

---

## Task 2.5: Backend — Finding Assignment (D17)

Covered in Task 2.1 routes. This task adds the notification trigger.

**Files:**
- Modify: `backend/app/services/finding_status_service.py` (add notification on assign)
- Create: `backend/tests/services/test_finding_assignment_notification.py`

- [ ] Write test: `test_assignment_sends_notification`
- [ ] Implement notification trigger on assignment
- [ ] Commit: `feat: add assignment notification (D17)`

---

## Task 2.6: Frontend — Assignment UI (D17)

**Files:**
- Modify: `frontend/src/pages/repo/RepoFindings.tsx` (add assign dropdown on rows)
- Create: `frontend/src/components/findings/AssignDropdown.tsx`
- Modify: `frontend/src/pages/PortfolioDashboard.tsx` (add "My Assigned Findings" for dev role)
- Create: `frontend/tests/components/AssignDropdown.test.tsx`

- [ ] Write test: assign dropdown shows group members
- [ ] Write test: DEV can only self-assign
- [ ] Implement AssignDropdown
- [ ] Add "My Assigned Findings" section for developers
- [ ] Update MSW handlers
- [ ] Run tests
- [ ] Commit: `feat: add finding assignment UI (D17)`

---

## Task 2.7: Backend — Bulk Actions (D19)

**Files:**
- Create: `backend/app/services/bulk_action_service.py`
- Create: `backend/app/schemas/bulk_action.py`
- Create: `backend/app/api/v1/bulk_actions.py`
- Create: `backend/tests/services/test_bulk_action_service.py`
- Create: `backend/tests/api/test_bulk_actions.py`
- Modify: `backend/app/api/v1/__init__.py`

**Route:** `POST /api/v1/findings/bulk`

**Body:**
```json
{
  "finding_ids": ["uuid1", "uuid2"],
  "action": "assign|status_change|mark_fp|mark_ra|raise_fp_request|raise_ra_request|create_jira|export",
  "params": {"assignee_id": "...", "status": "...", "justification": "..."}
}
```

**RBAC per D19:**

| Action | OA | SM | SE | TM | DEV |
|---|---|---|---|---|---|
| Assign | x | x | x | x | |
| Status change | x | x | x | x | |
| Mark FP/RA direct | x | x | | | |
| Raise FP/RA request | | | x | x | x |
| Create Jira | x | x | x | x | |
| Export | x | x | x | x | x |

- [ ] Write tests for each action type + RBAC enforcement
- [ ] Implement bulk service (delegates to individual services)
- [ ] Implement route
- [ ] Commit: `feat: add bulk actions endpoint (D19)`

---

## Task 2.8: Frontend — Bulk Actions UI (D19)

**Files:**
- Modify: `frontend/src/pages/repo/RepoFindings.tsx` (add checkbox + action bar)
- Create: `frontend/src/components/findings/BulkActionBar.tsx`
- Create: `frontend/tests/components/BulkActionBar.test.tsx`

- [ ] Write tests: checkbox selection, action bar visibility, role-filtered actions
- [ ] Implement BulkActionBar with role-aware action menu
- [ ] Wire to bulk endpoint
- [ ] Run tests
- [ ] Commit: `feat: add bulk actions UI (D19)`

---

## Task 2.9: Backend — Jira Integration (D18)

**Files:**
- Create: `backend/app/services/jira_service.py`
- Create: `backend/app/schemas/jira.py`
- Modify: `backend/app/api/v1/jira.py` (expand existing stub)
- Create: `backend/tests/services/test_jira_service.py`
- Create: `backend/tests/api/test_jira.py`

**Service:**
- `create_issue(finding_id, session)` — uses resolved Jira config (project → group → org), creates issue via Jira REST API
- `get_config(group_id?, project_id?, session)` — resolve config with inheritance
- `save_config(scope, config, session)` — save group or project level config

**Routes:**
- `POST /api/v1/findings/{finding_id}/jira`
- `GET /api/v1/groups/{group_id}/jira-config`
- `PUT /api/v1/groups/{group_id}/jira-config`
- `GET /api/v1/projects/{project_id}/jira-config`
- `PUT /api/v1/projects/{project_id}/jira-config`

- [ ] Write tests for config resolution (project → group → no config)
- [ ] Write tests for issue creation (pre-filled fields, URL stored on finding)
- [ ] Write tests for RBAC
- [ ] Implement service + routes
- [ ] Update MSW handlers
- [ ] Commit: `feat: add Jira integration service and routes (D18)`

---

## Task 2.10: Frontend — Jira Config & Create Issue UI (D18)

**Files:**
- Create: `frontend/src/components/findings/CreateJiraModal.tsx`
- Create: `frontend/src/components/settings/JiraConfigSection.tsx`
- Create: `frontend/src/api/hooks/useJira.ts`
- Create: `frontend/tests/components/CreateJiraModal.test.tsx`

- [ ] Write tests for Jira modal (pre-filled, editable, submit)
- [ ] Write tests for config section (save, test connection)
- [ ] Implement components + hook
- [ ] Run tests
- [ ] Commit: `feat: add Jira config and create issue UI (D18)`

---

## Task 2.11: Backend — Rule Effectiveness Analytics (D16)

**Files:**
- Create: `backend/app/services/rule_analytics_service.py`
- Create: `backend/app/schemas/rule_analytics.py`
- Create: `backend/app/api/v1/rule_analytics.py`
- Create: `backend/tests/services/test_rule_analytics_service.py`

**Service:**
- `get_rule_analytics(rule_id, time_window, session)` → metrics: total findings, FP rate, fix rate, MTTR, trend
- `get_all_rules_summary(time_window, session)` → per-rule summary for table

**Route:** `GET /api/v1/admin/rules/{rule_id}/analytics?time_window=90d`

- [ ] Write tests for metric calculations
- [ ] Write tests for time window filtering
- [ ] Implement service + route
- [ ] Commit: `feat: add rule effectiveness analytics (D16)`

---

## Task 2.12: Frontend — Rule Analytics UI (D16)

**Files:**
- Modify: `frontend/src/pages/PolicyRules.tsx` (add metrics columns)
- Create: `frontend/src/components/rules/RuleAnalyticsDetail.tsx`
- Create: `frontend/src/api/hooks/useRuleAnalytics.ts`
- Create: `frontend/tests/components/RuleAnalyticsDetail.test.tsx`

- [ ] Write tests for metrics display, warning icons, expandable detail
- [ ] Implement enhanced rules table + expandable analytics
- [ ] Add signal-vs-noise quadrant visualization
- [ ] Run tests
- [ ] Commit: `feat: add rule effectiveness analytics UI (D16)`

---

## Task 2.13: Frontend — Code Syntax Highlighting (#34)

**Files:**
- Modify: `frontend/src/components/findings/FindingDetail.tsx`
- Create: `frontend/src/components/ui/CodeBlock.tsx`
- Create: `frontend/tests/components/CodeBlock.test.tsx`

- [ ] Install: `npm install -D shiki`
- [ ] Write test: renders highlighted code with correct language
- [ ] Write test: theme-aware (dark/light from CSS variable)
- [ ] Implement CodeBlock with Shiki
- [ ] Wire into FindingDetail
- [ ] Run tests
- [ ] Commit: `feat: add code syntax highlighting on finding detail (#34)`

---

## Task 2.14: E2E — Finding Workflow Tests

**Files:**
- Create: `frontend/e2e/finding-workflow.spec.ts`

**Test scenarios:**
1. Login as SE → navigate to findings → sort by severity → verify order
2. Login as SE → click finding → change status to "In Review" → verify status badge
3. Login as DEV → click finding → "Request FP" → fill justification → submit
4. Login as SM → navigate to request queue → approve FP request → verify finding status
5. Login as TM → select multiple findings → bulk assign → verify
6. Accessibility scan on findings page, finding detail, request queue

- [ ] Write all E2E tests
- [ ] Run: `npx playwright test e2e/finding-workflow.spec.ts`
- [ ] Commit: `test: add finding workflow E2E tests`

---

## Task 2.15: Performance — Finding Endpoints

**Files:**
- Modify: `backend/tests/performance/locustfile.py` (add finding endpoints)

Add Locust tasks for:
- `GET /api/v1/projects/{id}/findings?page=1&per_page=25&status=open&sort=severity`
- `PATCH /api/v1/findings/{id}/status`
- `GET /api/v1/findings/{id}/history`
- `GET /api/v1/requests`

Target: p95 < 200ms for paginated finding list with 10k findings.

- [ ] Add new tasks to locustfile
- [ ] Run: `.venv/bin/locust -f tests/performance/locustfile.py --headless -u 50 -r 10 -t 60s`
- [ ] Record results
- [ ] Commit: `perf: add finding endpoint load tests`

---

## Doc Updates (per task, not batched)

Each task that adds endpoints must also:
1. Update `docs/RBAC-REFERENCE.md` with the endpoint's role matrix
2. Update MSW handlers in `frontend/src/mocks/handlers.ts`
3. Update `docs/UX-AUDIT-FINDINGS.md` decision column to DONE for resolved items
4. Run `/openapi-sync` after each endpoint group

## Completion Criteria

- [ ] All D13, D14, D15, D16, D17, D18, D19 endpoints implemented and tested
- [ ] Finding status transitions work correctly with RBAC enforcement
- [ ] FP/RA request workflow complete (raise → approve/reject)
- [ ] Bulk actions work for all roles per D19 matrix
- [ ] Jira config inheritance (project → group) works
- [ ] Rule analytics show FP rate, fix rate, MTTR per rule
- [ ] Code highlighting on finding detail
- [ ] E2E tests pass for multi-role finding workflow
- [ ] p95 < 200ms for finding list pagination
- [ ] All pages pass axe-core WCAG 2.1 AA
