# Phase 4.5 — UI Stabilization & UX Polish: Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all 32 design decisions (D1–D32) + ADR-034 from the Phase 4.5 UX audit, delivering a production-ready portal with complete finding lifecycle, scan management, RBAC enforcement, and enterprise admin features.

**Architecture:** 7 sub-plans executing in dependency order. Plan 1 (Foundation) runs first, Plans 2–6 run in parallel, Plan 7 runs last. Each plan covers backend + frontend + CLI (where applicable) + tests (unit, integration, E2E, security, performance, accessibility).

**Tech Stack:** FastAPI + SQLAlchemy 2.0 async (backend), React 19 + TanStack Query/Router + Tailwind (frontend), Go + tree-sitter (CLI), Playwright (E2E + a11y), Vitest (frontend unit), pytest (backend unit), Locust (performance), factory-boy (test fixtures), MSW (mock API), axe-core (accessibility).

---

## Execution Order & Parallelism

```
Phase 4.5 Execution Timeline

Week 1-2:  [Plan 1: Foundation          ]
Week 3-6:  [Plan 2: Finding Workflow     ] ← parallel
           [Plan 3: Scan Lifecycle       ] ← parallel
           [Plan 4: User & Auth          ] ← parallel
           [Plan 5: Admin & Config       ] ← parallel
           [Plan 6: Navigation & UX      ] ← parallel
Week 7:    [Plan 7: Portfolio Views      ]
Week 8:    [Integration testing, E2E, perf, security review]
```

---

## Documentation Strategy (All Plans)

Docs update **with** the code, not after. Every plan agent must update relevant docs as part of each task's commit.

| Doc | Updated by | When |
|---|---|---|
| `docs/PHASE-4.5-DECISIONS.md` | Any plan agent | Mark decision as IMPLEMENTED when all its tasks are done |
| `docs/UX-AUDIT-FINDINGS.md` | Any plan agent | Update Decision column to DONE when item is shipped |
| `docs/09-rbac.md` | Plan 2, 4 | When RBAC changes land (D12, D17 role refinements) |
| `docs/RBAC-REFERENCE.md` | Plan 2, 4, 5 | When any endpoint with RBAC is added — add to permission matrix |
| `docs/DECISION-LOG.md` | Plan 1 | When new ADRs are created during implementation |
| `docs/api-contracts/phase45-endpoints.yaml` | All plans | When endpoint shape changes during implementation (spec stays in sync) |
| `CLAUDE.md` | Plan 5, 6 | When new CLI commands (D27 rule sync) or skills are added |
| `README.md` | Plan 7 (final) | Feature summary update at the end |
| `docs/08-roadmap.md` | Plan 7 (final) | Mark Phase 4.5 complete |
| Backend docstrings | All plans | Every new service/route/model gets docstrings at creation |
| MSW handlers (`mocks/handlers.ts`) | All frontend tasks | Every new endpoint gets a corresponding mock handler |
| OpenAPI spec | All backend tasks | Run `/openapi-sync` after each endpoint group is complete |

**Rule:** If a task adds/changes an API endpoint, RBAC rule, or user-facing feature, the corresponding doc update is part of that task's commit — not a separate task.

---

## Testing Strategy (All Plans)

Every plan includes these test layers:

| Layer | Tool | What | When |
|---|---|---|---|
| **Unit (backend)** | pytest + factory-boy | Service logic, model validation, schema serialization | Every task |
| **Unit (frontend)** | Vitest + Testing Library + MSW | Component render, hook behavior, RBAC guards | Every task |
| **Integration (backend)** | pytest + httpx AsyncClient | Full API endpoint request → response | Per endpoint group |
| **Integration (frontend)** | Vitest + MSW | Page-level render with mocked API | Per page |
| **E2E** | Playwright | Full browser flow across frontend → backend | Per user journey |
| **Accessibility** | Playwright + axe-core | WCAG 2.1 AA compliance per page | Per page (D32) |
| **Security** | bandit + npm audit + RBAC matrix tests | Auth, authorization, injection, OWASP | Per plan completion |
| **Performance** | Locust (backend) + Lighthouse (frontend) | API latency p50/p95/p99, page load, bundle size | Plan 1 baseline + Plan 7 final |
| **UI Visual** | Playwright screenshots | Theme consistency, responsive breakpoints | Per page (D29) |

---

## Sub-Plan Index

### [Plan 1: Foundation](#plan-1-foundation) (Week 1–2)
**Decisions:** API contract design, DB migrations, D25 (toast), ADR-034 (finding identity)
**Prerequisite for:** All other plans

### [Plan 2: Finding Workflow](#plan-2-finding-workflow) (Week 3–6)
**Decisions:** D13, D14, D15, D16, D17, D18, D19
**Depends on:** Plan 1

### [Plan 3: Scan Lifecycle](#plan-3-scan-lifecycle) (Week 3–6)
**Decisions:** D1, D2, D20, D21
**Depends on:** Plan 1

### [Plan 4: User & Auth](#plan-4-user-auth) (Week 3–6)
**Decisions:** D6, D7, D9, D10, D11, D12, D30
**Depends on:** Plan 1

### [Plan 5: Admin & Config](#plan-5-admin-config) (Week 3–6)
**Decisions:** D3, D5, D26, D27, D28
**Depends on:** Plan 1

### [Plan 6: Navigation & UX](#plan-6-navigation-ux) (Week 3–6)
**Decisions:** D4, D8, D22, D23, D24, D29, D31, D32
**Depends on:** Plan 1 (partially)

### [Plan 7: Portfolio Views](#plan-7-portfolio-views) (Week 7)
**Decisions:** D23 (cert tracker, PQC migration progress)
**Depends on:** Plans 2, 3

---

## Plan 1: Foundation

**Goal:** Database schema ready, API contracts documented, global UI patterns (toast, pagination), finding identity matching implemented.

### Task 1.1: API Contract Document

**Files:**
- Create: `docs/api-contracts/phase45-endpoints.yaml` (OpenAPI 3.1 spec)
- Modify: `backend/app/api/v1/__init__.py` (router registration)

Document all new endpoints from D1–D32 in OpenAPI format. This becomes the source of truth for frontend and backend teams.

**Endpoint groups:**

| Group | Endpoints | Decision |
|---|---|---|
| Finding status | PATCH /findings/{id}/status, GET /findings/{id}/history | D14 |
| FP/RA requests | POST /findings/{id}/request, GET /requests, POST /requests/{id}/approve, POST /requests/{id}/reject | D15 |
| Finding assignment | PATCH /findings/{id}/assign | D17 |
| Finding bulk | POST /findings/bulk-action | D19 |
| Jira | POST /findings/{id}/jira, GET /groups/{id}/jira-config, PUT /groups/{id}/jira-config | D18 |
| Scan management | GET /scans (global queue), POST /scans/{id}/rerun | D20 |
| Scan scheduling | GET /projects/{id}/schedule, PUT /projects/{id}/schedule | D20 |
| Scan provenance | GET /scans/{id}/provenance, POST /scans/promote | D21 |
| User lifecycle | PUT /admin/users/{id}/role, POST /admin/users/{id}/disable, POST /admin/users/{id}/enable, DELETE /admin/users/{id} | D9 |
| User creation | POST /admin/users/invite, POST /admin/users/direct | D10 |
| Password | PUT /auth/password, PUT /admin/users/{id}/reset-password | D6 |
| API keys | POST /auth/api-keys, GET /auth/api-keys, DELETE /auth/api-keys/{id}, GET /admin/api-keys, DELETE /admin/api-keys/{id} | D7 |
| Policy cascade | GET /policy, PUT /policy, GET /groups/{id}/policy, PUT /groups/{id}/policy, GET /projects/{id}/policy, PUT /projects/{id}/policy | D26 |
| Custom rules | POST /admin/rules, GET /admin/rules, PUT /admin/rules/{id}, DELETE /admin/rules/{id}, POST /admin/rules/{id}/test | D27 |
| Rule sync (CLI) | GET /rules/delta?since={timestamp} | D27 |
| Audit log | GET /admin/audit-log (with filters), GET /admin/audit-log/export | D28 |
| LLM config | GET /admin/llm-config, PUT /admin/llm-config, POST /admin/llm-config/test | D5 |
| Integrations | POST /admin/integrations/{provider}/connect, DELETE /admin/integrations/{provider}, POST /admin/integrations/{provider}/test, GET /admin/integrations/{provider}/repos | D3 |
| Artifact registries | CRUD /admin/registries | D2 |
| Org settings | GET /admin/settings, PUT /admin/settings (includes labels D4, retention D28, env stages D21) | D4, D25 |
| Notifications | GET /notifications?page&per_page (fix 422) | existing fix |
| Forgot password | POST /auth/forgot-password, POST /auth/reset-password | D30 |
| Search | GET /search?q={query}&type={project|finding} | D22 |
| Environment | GET /admin/environments, PUT /admin/environments | D21 |

- [ ] Step 1: Write OpenAPI 3.1 spec covering all endpoint groups above
- [ ] Step 2: Review spec against D1–D32 decisions for completeness
- [ ] Step 3: Generate TypeScript types from spec: `npx openapi-typescript docs/api-contracts/phase45-endpoints.yaml -o frontend/src/types/api-generated.d.ts`
- [ ] Step 4: Commit

### Task 1.2: Database Migration — Phase 4.5 Schema

**Files:**
- Create: `backend/app/db/migrations/versions/007_phase45_schema.py`
- Modify: `backend/app/models/` (multiple model files)

**Schema changes:**

```sql
-- D4: Customizable labels
ALTER TABLE organisations ADD COLUMN labels JSONB DEFAULT '{"group": "Group", "project": "Project"}';

-- D6: Auth source
ALTER TABLE users ADD COLUMN auth_source VARCHAR(20) NOT NULL DEFAULT 'local';

-- D7: API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D9: User soft-delete
ALTER TABLE users ADD COLUMN disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN deletion_policy VARCHAR(20) DEFAULT 'retain';

-- D11: User activity
ALTER TABLE users ADD COLUMN last_active_at TIMESTAMPTZ;

-- D12: Per-group roles
ALTER TABLE user_groups ADD COLUMN role VARCHAR(50);

-- D14: Finding status model
ALTER TABLE findings ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN assigned_to UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN reopen_count INT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN last_reopened_at TIMESTAMPTZ;

CREATE TABLE finding_status_history (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_status VARCHAR(20),
    to_status VARCHAR(20) NOT NULL,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D15: FP/RA requests
CREATE TABLE finding_requests (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_type VARCHAR(10) NOT NULL, -- 'fp' or 'ra'
    justification TEXT NOT NULL,
    reason_category VARCHAR(50),
    review_date DATE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D18: Jira config per group/project
CREATE TABLE jira_configs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    jira_project_key VARCHAR(20) NOT NULL,
    default_issue_type VARCHAR(50) DEFAULT 'Bug',
    priority_mapping JSONB DEFAULT '{}',
    custom_fields JSONB DEFAULT '{}',
    default_assignee VARCHAR(255),
    labels JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT jira_config_scope CHECK (
        (group_id IS NOT NULL AND project_id IS NULL) OR
        (group_id IS NULL AND project_id IS NOT NULL)
    )
);

-- D20: Scan scheduling
ALTER TABLE projects ADD COLUMN schedule_cron VARCHAR(100);
ALTER TABLE projects ADD COLUMN schedule_timezone VARCHAR(50) DEFAULT 'UTC';
ALTER TABLE groups ADD COLUMN schedule_cron VARCHAR(100);
ALTER TABLE groups ADD COLUMN schedule_timezone VARCHAR(50) DEFAULT 'UTC';
ALTER TABLE organisations ADD COLUMN default_schedule_cron VARCHAR(100);
ALTER TABLE organisations ADD COLUMN default_schedule_timezone VARCHAR(50) DEFAULT 'UTC';
ALTER TABLE organisations ADD COLUMN allow_project_schedule_override BOOLEAN DEFAULT true;

-- D21: Scan provenance & environment
ALTER TABLE scans ADD COLUMN branch VARCHAR(255);
ALTER TABLE scans ADD COLUMN commit_sha VARCHAR(64);
ALTER TABLE scans ADD COLUMN tag VARCHAR(255);
ALTER TABLE scans ADD COLUMN image_ref VARCHAR(512);
ALTER TABLE scans ADD COLUMN image_digest VARCHAR(128);
ALTER TABLE scans ADD COLUMN artifact_filename VARCHAR(512);
ALTER TABLE scans ADD COLUMN artifact_checksum VARCHAR(128);
ALTER TABLE scans ADD COLUMN environment VARCHAR(50);
ALTER TABLE scans ADD COLUMN promoted_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN promoted_by UUID REFERENCES users(id);

CREATE TABLE environment_stages (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    display_order INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D26: Policy cascade
CREATE TABLE policy_overrides (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    enabled BOOLEAN,
    severity_override VARCHAR(20),
    locked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT policy_scope CHECK (
        (group_id IS NULL AND project_id IS NULL) OR
        (group_id IS NOT NULL AND project_id IS NULL) OR
        (group_id IS NULL AND project_id IS NOT NULL)
    )
);

-- D27: Custom rules
CREATE TABLE custom_rules (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    language VARCHAR(50) NOT NULL,
    content TEXT NOT NULL, -- OpenGrep YAML
    parent_rule_id VARCHAR(255), -- forked from built-in
    is_active BOOLEAN DEFAULT true,
    validated_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D28: Audit log enhancements
ALTER TABLE audit_log ADD COLUMN action_type VARCHAR(50);
ALTER TABLE audit_log ADD COLUMN project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE audit_log ADD COLUMN group_id UUID REFERENCES groups(id) ON DELETE SET NULL;
CREATE INDEX idx_audit_log_action_type ON audit_log(action_type);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);

-- D5: LLM config
CREATE TABLE llm_configs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'anthropic', 'openai', 'ollama', 'custom', 'disabled'
    api_url VARCHAR(512),
    model VARCHAR(255),
    temperature FLOAT DEFAULT 0.1,
    max_tokens INT DEFAULT 2048,
    custom_instructions TEXT,
    privacy_strip_comments BOOLEAN DEFAULT false,
    privacy_anonymize_vars BOOLEAN DEFAULT false,
    cache_ttl_days INT DEFAULT 7,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ADR-034: Finding identity
ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64);
ALTER TABLE findings ADD COLUMN normalized_signature TEXT;
CREATE INDEX idx_findings_fingerprint ON findings(project_id, fingerprint);
CREATE INDEX idx_findings_rule_file ON findings(project_id, rule_id, file_path);

-- D3: Integration tokens
CREATE TABLE integration_tokens (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'github', 'gitlab', 'bitbucket', 'jira', 'teams'
    base_url VARCHAR(512),
    token_hash VARCHAR(64) NOT NULL,
    token_prefix VARCHAR(20),
    scopes JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'active',
    last_tested_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D2: Artifact registries
CREATE TABLE artifact_registries (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    registry_type VARCHAR(50) NOT NULL, -- 'jfrog', 'ecr', 'gcr', 'acr', 'docker_hub', 'harbor', 'gitlab', 'custom'
    url VARCHAR(512) NOT NULL,
    auth_method VARCHAR(50), -- 'token', 'userpass', 'iam_role', 'service_account'
    auth_config JSONB DEFAULT '{}', -- encrypted credentials
    include_filters JSONB DEFAULT '[]',
    exclude_filters JSONB DEFAULT '[]',
    last_tested_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- [ ] Step 1: Write Alembic migration `007_phase45_schema.py` with all tables above
- [ ] Step 2: Write downgrade function
- [ ] Step 3: Update SQLAlchemy models to match new columns/tables
- [ ] Step 4: Run migration: `alembic upgrade head`
- [ ] Step 5: Verify with `\d` commands in psql
- [ ] Step 6: Commit

### Task 1.3: Backend — Pagination & Filtering Framework

**Files:**
- Create: `backend/app/schemas/pagination.py`
- Create: `backend/app/services/pagination_service.py`
- Create: `backend/tests/services/test_pagination.py`

Standard pagination pattern (D11) reusable across all list endpoints.

- [ ] Step 1: Write tests for pagination utility
- [ ] Step 2: Implement `PaginatedResponse[T]` generic schema and `paginate()` service function
- [ ] Step 3: Verify tests pass
- [ ] Step 4: Commit

### Task 1.4: Backend — Audit Log Service

**Files:**
- Create: `backend/app/services/audit_service.py`
- Create: `backend/tests/services/test_audit_service.py`

Centralized audit logging used by all plans.

- [ ] Step 1: Write tests for audit log creation with action types
- [ ] Step 2: Implement `AuditService.log(action_type, actor, target, details, session)`
- [ ] Step 3: Verify tests pass
- [ ] Step 4: Commit

### Task 1.5: Backend — Finding Identity Matching (ADR-034)

**Files:**
- Create: `backend/app/services/finding_matcher.py`
- Create: `backend/tests/services/test_finding_matcher.py`
- Modify: `cli/internal/types/finding.go` (add Fingerprint field)
- Create: `cli/internal/scanner/fingerprint.go`
- Create: `cli/internal/scanner/fingerprint_test.go`

**CLI side (Go):**
- [ ] Step 1: Write test for normalized code signature generation
- [ ] Step 2: Implement `ComputeFingerprint(finding Finding) string` — normalize + SHA-256
- [ ] Step 3: Write test for normalization rules (strip comments, collapse whitespace, normalize literals)
- [ ] Step 4: Implement per-language normalizers for T1 (Java, Python, Go, JS/TS)
- [ ] Step 5: Add `Fingerprint` field to `Finding` struct, populate during scan
- [ ] Step 6: Verify tests pass
- [ ] Step 7: Commit

**Backend side (Python):**
- [ ] Step 8: Write tests for cross-scan matching: exact match, fuzzy match, unmatched handling
- [ ] Step 9: Implement `FindingMatcher.match(new_findings, existing_findings)` → matched/new/resolved
- [ ] Step 10: Write tests for status preservation on match (FP/RA stay, Open gets updated)
- [ ] Step 11: Implement status-aware matching per D14 rules
- [ ] Step 12: Write tests for file rename detection
- [ ] Step 13: Implement git rename mapping integration
- [ ] Step 14: Verify all tests pass
- [ ] Step 15: Commit

### Task 1.6: Frontend — Toast System (D25)

**Files:**
- Create: `frontend/src/components/ui/Toast.tsx`
- Create: `frontend/src/lib/use-toast.ts`
- Modify: `frontend/src/App.tsx` (add Toaster provider)
- Create: `frontend/tests/components/Toast.test.tsx`

- [ ] Step 1: Write tests for toast hook (show, dismiss, auto-dismiss)
- [ ] Step 2: Implement `useToast` hook + `<Toaster />` component
- [ ] Step 3: Verify tests pass
- [ ] Step 4: Commit

### Task 1.7: Frontend — Standard Pagination Component

**Files:**
- Create: `frontend/src/components/ui/Pagination.tsx`
- Create: `frontend/tests/components/Pagination.test.tsx`

- [ ] Step 1: Write tests for pagination component (page change, size change, display)
- [ ] Step 2: Implement reusable `<Pagination>` component matching D11 pattern
- [ ] Step 3: Verify tests pass
- [ ] Step 4: Commit

### Task 1.8: Backend — Factory Boy Test Fixtures

**Files:**
- Create: `backend/tests/factories.py`

Reusable factories for all test data.

- [ ] Step 1: Create factories for: UserFactory, ProjectFactory, GroupFactory, ScanFactory, FindingFactory, OrgFactory
- [ ] Step 2: Verify factories produce valid model instances
- [ ] Step 3: Commit

### Task 1.9: E2E — Playwright Setup

**Files:**
- Create: `frontend/playwright.config.ts`
- Create: `frontend/e2e/helpers.ts` (login helper, page helpers)
- Create: `frontend/e2e/smoke.spec.ts` (basic smoke test)

- [ ] Step 1: Configure Playwright with base URL, projects (chromium), timeouts
- [ ] Step 2: Write login helper that authenticates via API and sets session
- [ ] Step 3: Write smoke test: login → dashboard loads → sidebar visible
- [ ] Step 4: Add axe-core helper for accessibility scanning per page
- [ ] Step 5: Verify smoke test passes against running dev stack
- [ ] Step 6: Commit

### Task 1.10: Performance — Baseline

**Files:**
- Create: `backend/tests/performance/locustfile.py`

- [ ] Step 1: Write Locust tasks for existing endpoints: login, portfolio summary, assets, projects
- [ ] Step 2: Run baseline: 50 concurrent users, 60s duration
- [ ] Step 3: Record p50/p95/p99 latencies as baseline
- [ ] Step 4: Commit

---

## Plan 2: Finding Workflow

**Goal:** Complete finding lifecycle — status model, FP/RA requests, assignments, bulk actions, Jira integration, rule analytics.
**Depends on:** Plan 1 (migration, pagination, audit service, finding matcher)
**Decisions:** D13, D14, D15, D16, D17, D18, D19

### Task 2.1: Backend — Finding Status Model (D14)
- Finding status enum, status transition validation, auto-transitions on scan
- Mandatory justification for RA/FP
- Status history recording via audit service
- MTTR calculation service

### Task 2.2: Frontend — Finding Table UX (D13)
- Sortable columns, server-side pagination, file-grouped view toggle
- "Detection" column rename (Pattern/Taint)
- Status filter bar with counts

### Task 2.3: Backend — FP/RA Request Workflow (D15)
- Request creation, approval queue, rejection flow
- Soft rate limiting (advisory)
- RBAC enforcement per D17 matrix

### Task 2.4: Frontend — FP/RA Request UI (D15)
- Request modal with justification form
- Approval queue page (sidebar badge)
- Approve/reject actions

### Task 2.5: Backend — Finding Assignment (D17)
- Assign endpoint with scope validation (group-level)
- Auto-transition to "In Review" on assignment
- Notification trigger

### Task 2.6: Frontend — Assignment UI (D17)
- Assign dropdown on finding detail
- "My Assigned Findings" section on developer dashboard

### Task 2.7: Backend — Bulk Actions (D19)
- Bulk endpoint accepting finding IDs + action
- RBAC-scoped per D17 matrix
- Bulk Jira creation (single ticket with multiple findings)

### Task 2.8: Frontend — Bulk Actions UI (D19)
- Checkbox selection, action bar, role-filtered action menu

### Task 2.9: Backend — Jira Integration (D18)
- Two-tier config (org connection + group/project mapping)
- Issue creation with pre-filled fields
- Bidirectional status sync webhook endpoint

### Task 2.10: Frontend — Jira Config & Create Issue UI (D18)
- Group/project settings Jira config section
- "Create Jira Issue" modal from finding detail

### Task 2.11: Backend — Rule Effectiveness Analytics (D16)
- Per-rule metrics: FP rate, fix rate, MTTR, trend
- Time-windowed aggregation (30d/90d/180d/1y/all)
- Signal-vs-noise quadrant calculation

### Task 2.12: Frontend — Rule Analytics UI (D16)
- Enhanced policy rules table with metrics columns
- Expandable detail with trend chart and quadrant
- Automated warning icons

### Task 2.13: Frontend — Code Syntax Highlighting (#34)
- Shiki/Prism integration on FindingDetail
- Theme-aware (dark/light)

### Task 2.14: E2E — Finding Workflow Tests
- Playwright: create finding → assign → change status → mark FP → verify audit trail
- Playwright: bulk select → bulk assign → verify
- Accessibility scan on findings page

### Task 2.15: Performance — Finding Endpoints
- Locust: finding list with 10k findings, pagination, sorting, filtering
- Target: p95 < 200ms for paginated list

---

## Plan 3: Scan Lifecycle

**Goal:** Scan modal, progress tracking, queue view, scheduling, provenance, environment tagging.
**Depends on:** Plan 1
**Decisions:** D1, D2, D20, D21

### Task 3.1: Backend — Scan Progress WebSocket (D20 #36)
- WebSocket endpoint for scan progress events
- Taskiq worker emits: queued → cloning → scanning → generating → done/failed

### Task 3.2: Frontend — Scan Modal (D1)
- 3-tab modal: Repository, Container Image, Artifact
- Context-aware (dashboard vs project page)
- Pre-filled from project scan sources

### Task 3.3: Frontend — Scan Progress UI (D20 #36)
- WebSocket listener, progress bar on project page
- Toast notification on completion

### Task 3.4: Backend — Scan Queue API (D20 #38)
- Global scans list endpoint with filters (status, project, trigger type)
- RBAC-scoped per D12

### Task 3.5: Frontend — Scan Queue Page (D20 #38)
- Global "Scans" page in sidebar
- Table with project, trigger, status, duration, triggered by

### Task 3.6: Backend — Scan Scheduling (D20 #39)
- Three-tier schedule (org → group → project)
- Cron expression storage + scheduler worker
- Admin toggle for project override

### Task 3.7: Frontend — Schedule Config UI (D20 #39)
- Schedule settings in project/group/org settings
- Preset selector (daily/weekly) + time + timezone

### Task 3.8: Backend — Scan Provenance & Promotion (D21)
- Provenance fields captured on scan creation
- Promote endpoint with tag transfer logic
- Environment stages CRUD

### Task 3.9: Frontend — Environment Tags & Promotion UI (D21)
- Environment badge on scan rows
- "Promote to..." dropdown in scan history
- Environment filter on portfolio dashboard

### Task 3.10: Backend — Stale Scan Warning (#37) + Rerun (#40)
- Stale threshold check (org-configurable)
- Rerun endpoint cloning scan config

### Task 3.11: Frontend — Stale Warning & Rerun UI
- Banner on project page when stale
- "Rerun" button on scan history rows

### Task 3.12: Backend — Artifact Registry CRUD (D2)
- Registry management endpoints
- Connection testing per registry type

### Task 3.13: Frontend — Artifact Registry Admin Page (D2)
- Admin > Artifact Registries page
- Registry CRUD with test connection

### Task 3.14: E2E — Scan Lifecycle Tests
- Playwright: trigger scan → see progress → scan completes → results visible
- Playwright: promote scan to production → verify environment tag
- Accessibility scan on scan pages

### Task 3.15: Performance — Scan Endpoints
- Locust: scan queue with 1k scans, pagination + filters
- WebSocket connection stress test (50 concurrent)

---

## Plan 4: User & Auth

**Goal:** User lifecycle, API keys, password management, role resolution, login improvements.
**Depends on:** Plan 1
**Decisions:** D6, D7, D9, D10, D11, D12, D30

### Task 4.1: Backend — Password Management (D6)
- Self-service password change endpoint
- Admin force-reset endpoint
- Auth source field on user model

### Task 4.2: Backend — API Key Management (D7)
- CRUD endpoints for API keys
- Scopes capped by role
- Key hashing (SHA-256), prefix display

### Task 4.3: Frontend — Profile Page Overhaul (D6, D7)
- Password change form (conditional on auth_source)
- API key management section
- MFA disabled button with Phase 6 tooltip

### Task 4.4: Backend — User Lifecycle (D9)
- Role editing with downgrade handling (auto-revoke over-scoped keys)
- Disable (soft-lock) with API key suspension
- Delete (two-step: require disabled first, 30-day grace)
- Last-OA protection

### Task 4.5: Frontend — User Management Page (D9, D10, D11)
- Role dropdown, disable/delete actions
- Dual creation flow (invite + direct add)
- Server-side pagination + last-active column
- User detail drawer

### Task 4.6: Backend — Role Resolution (D12)
- `getEffectiveRole(user, group)` = max(group_role, global_role)
- Add nullable role column to user_groups
- Permission checking middleware updated

### Task 4.7: Backend — Forgot Password (D30)
- Reset link email (if SMTP configured)
- Reset token generation + validation

### Task 4.8: Frontend — Login Page Updates (D30, D8)
- Forgot password link + flow
- Hide SSO buttons (D8 #13, #14)
- Keep "Invalid credentials" generic (D30 #78)

### Task 4.9: Backend — Break-Glass Recovery (D9)
- CLI command: `cradar admin reset-password`
- Recovery key generation at org setup
- `/recover` endpoint

### Task 4.10: E2E — User & Auth Tests
- Playwright: login → change password → re-login with new password
- Playwright: admin creates user → user logs in → sees correct RBAC
- Playwright: disable user → verify login blocked
- Accessibility scan on profile/login/user management pages

### Task 4.11: Security — Auth Tests
- RBAC matrix test: every role × every endpoint
- API key scope enforcement test
- Password policy enforcement test
- Rate limiting on login endpoint

---

## Plan 5: Admin & Config

**Goal:** Integration management, LLM config, policy cascade, custom rules, audit log.
**Depends on:** Plan 1
**Decisions:** D3, D5, D26, D27, D28

### Task 5.1: Backend — Integration Management (D3)
- PAT/token CRUD per provider
- Connection testing
- Repo discovery + sync
- Token encryption at rest

### Task 5.2: Frontend — Integration Management Page (D3)
- Provider cards with connect/disconnect
- PAT modal per provider
- Repo picker with import flow

### Task 5.3: Backend — LLM Configuration (D5)
- LLM config CRUD
- Provider-specific validation
- Test connection endpoint
- Credential encryption

### Task 5.4: Frontend — LLM Admin Page (D5)
- Provider selector with per-provider fields
- Test connection button
- Privacy controls toggles
- Custom instructions textarea

### Task 5.5: Backend — AI Remediation Wiring (D5)
- "Get Fix" endpoint using configured LLM provider
- Consent verification
- Response caching with TTL
- Code privacy transforms (strip comments, anonymize vars)

### Task 5.6: Frontend — Finding Remediation UX (D5)
- Consent modal with code preview
- Side-by-side original vs fix display
- "Copy Fix" button
- Provider name + confidence score display

### Task 5.7: Backend — Policy Cascade (D26)
- Cascading config resolution: project → group → org
- Lock mechanism (OA only)
- Policy override CRUD with scope validation

### Task 5.8: Frontend — Policy Configuration UI (D26)
- Policy rules page with override indicators
- Severity override per rule
- Lock icon for locked rules
- Scope selector (org/group/project)

### Task 5.9: Backend — Custom Rules (D27)
- Rule upload + OpenGrep schema validation
- Dry-run testing against a project
- Rule forking from built-in
- Delta sync endpoint for CLI

### Task 5.10: CLI — Custom Rule Auto-Sync (D27)
- Check portal for delta rules at scan start
- Download to `~/.cradar/rules/`
- Graceful fallback on sync failure
- Use `.cradar.yml` for portal URL + auth

### Task 5.11: Frontend — Custom Rules UI (D27)
- Rule upload modal with validation feedback
- Fork rule flow
- Rule search/filter bar (language, source, severity, status)

### Task 5.12: Backend — Audit Log Enhancements (D28)
- Filtered query (date range, actor, action type, group/project)
- CSV export endpoint
- Webhook forwarding (JSON POST to configured URL)
- Retention policy enforcement (background job)

### Task 5.13: Frontend — Audit Log Page (D28)
- Date range picker, user filter, action type filter
- Server-side pagination
- CSV export button
- Webhook config in admin settings

### Task 5.14: E2E — Admin Tests
- Playwright: connect git provider → import repos → verify in project list
- Playwright: configure LLM → get fix on finding → verify consent flow
- Playwright: create custom rule → verify in rule list → trigger scan
- Accessibility scan on admin pages

### Task 5.15: Security — Admin Tests
- Integration token encryption verification
- LLM API key not exposed in responses
- Custom rule injection prevention (YAML validation)
- Audit log tamper-resistance verification

---

## Plan 6: Navigation & UX

**Goal:** Navigation overhaul, onboarding, theme fixes, accessibility, visual polish.
**Depends on:** Plan 1 (partially)
**Decisions:** D4, D8, D22, D23, D24, D29, D31, D32

### Task 6.1: Frontend — Tab Consolidation (D22 #41)
- Reduce project tabs from 10+ to 6
- Merge Quantum → Compliance, SBOM → Dependencies
- Settings absorbs scan sources, Jira config, notifications, schedule

### Task 6.2: Frontend — Breadcrumbs (D22 #42)
- Breadcrumb component: Org → Group → Project → Tab
- Integrated in TopBar

### Task 6.3: Frontend — Global Search (D22 #43)
- Ctrl+K command palette
- Project search + finding search (Phase 4.5 scope)

### Task 6.4: Frontend — Sidebar Overhaul (D22 #46, #47, D4)
- Lucide React icons replacing Unicode
- Notification bell in TopBar
- Groups with projects in sidebar (collapsible)
- Customizable labels (D4)

### Task 6.5: Frontend — Onboarding Wizard (D24 #51)
- 3-step wizard for first OA/SM login
- Connect provider → Import projects → First scan

### Task 6.6: Frontend — Empty States (D24 #52–#55)
- Reusable EmptyState component
- Per-context copy and action buttons
- Guest role info banner

### Task 6.7: Frontend — Theme & Visual Fixes (D29)
- Move hardcoded colors to CSS variables (#67, #68)
- Fix Crystal theme contrast (#69)
- Responsive breakpoints ≥1024px (#70, #71, #72)
- Standardize badges to CSS classes (#73)
- Define type scale (#74)
- Theme preview thumbnails (#75)

### Task 6.8: Frontend — Keyboard Shortcuts Modal (D8 #11)
- Replace alert with styled modal
- Shortcut reference table

### Task 6.9: Frontend — Notification & Integration Polish (D31)
- Webhook test button (#83)
- Synced repos indicator per provider (#85)
- Token rotation UI + age warning (#86)

### Task 6.10: Frontend — Accessibility (D32)
- Keyboard navigation for tables, sidebar, filters (#87)
- `scope` attributes on table headers (#89)
- `aria-label` on icon-only buttons (#91)
- `:focus-visible` states on all interactive elements (#92)
- Focus trap in modals (#93)
- Graph accessibility: summary + table alt view + visual SVG legend (#90)

### Task 6.11: E2E — Navigation & UX Tests
- Playwright: navigate via breadcrumbs → verify page loads
- Playwright: Ctrl+K → search project → navigate → verify
- Playwright: onboarding wizard flow (fresh user)
- Playwright: responsive test at 1024px breakpoint
- Playwright: theme switch → verify no broken contrast

### Task 6.12: Accessibility — Full A11y Audit
- axe-core scan on every page (Playwright)
- WCAG 2.1 AA compliance report
- Fix any violations found

---

## Plan 7: Portfolio Views

**Goal:** Certificate tracker and PQC migration progress views.
**Depends on:** Plans 2 (finding data), 3 (scan data)
**Decisions:** D23 (cert tracker, PQC migration)

### Task 7.1: Backend — Certificate Tracker API
- Endpoint returning all certificate findings across projects
- Expiry calculation + color coding (green/amber/red/black)
- Notification triggers for approaching expiry

### Task 7.2: Frontend — Certificate Tracker Page (D23 #48)
- Timeline/calendar view of cert expiry dates
- Color-coded by time to expiry
- Filter by project/group

### Task 7.3: Backend — PQC Migration Progress API
- Aggregate migration posture: % quantum-vulnerable
- Per-algorithm-family progress (RSA → ML-KEM, ECDSA → ML-DSA)
- Lagging projects identification

### Task 7.4: Frontend — PQC Migration Progress (D23 #49)
- Read-only dashboard section within Portfolio Compliance
- Progress bars by algorithm family
- Project counts per migration stage
- On-track indicator vs quantum deadline

### Task 7.5: E2E — Portfolio Tests
- Playwright: navigate to cert tracker → verify certs displayed with correct colors
- Playwright: navigate to compliance → verify PQC migration section visible
- Accessibility scan on portfolio pages

### Task 7.6: Performance — Final Benchmark
- Locust: all new endpoints under load (100 concurrent users, 5 min)
- Compare against Plan 1 baseline
- Lighthouse audit on all new/modified pages
- Bundle size check (target: < 500KB gzipped)

---

## Cross-Cutting Final Tasks

### Task 8.1: Security Review
- Run `/sec-review` on all Go changes
- Run `/sec-py` on all Python changes
- Run `/sec-fe` on all frontend changes
- Run `/dep-audit` on all workstreams
- RBAC matrix test: every role × every new endpoint
- Verify no secrets in code/config

### Task 8.2: Documentation Verification
- **Note:** Docs are updated continuously per the Documentation Strategy above. This task verifies completeness.
- Verify all D1–D32 marked as IMPLEMENTED in `docs/PHASE-4.5-DECISIONS.md`
- Verify all 93 items marked DONE in `docs/UX-AUDIT-FINDINGS.md`
- Verify `docs/RBAC-REFERENCE.md` covers every new endpoint
- Verify `docs/09-rbac.md` reflects D12/D17 role changes
- Verify `CLAUDE.md` is current (new commands, conventions, phase status)
- Update `docs/08-roadmap.md` marking Phase 4.5 complete
- Update `README.md` with Phase 4.5 feature summary
- Run `/openapi-sync` for final spec validation
- Regenerate TypeScript types and verify no drift

### Task 8.3: Integration E2E Suite
- Full user journey: sign up org → connect provider → import repo → scan → find findings → assign → fix → mark resolved → promote to prod
- Multi-role scenario: admin configures, SM creates policy, SE reviews findings, DEV gets fix, TM assigns
- Verify audit trail completeness across entire journey
- Run full axe-core accessibility sweep across all pages

---

## Skills Used Per Plan

| Plan | Skills |
|---|---|
| Plan 1 | `/db-migrate`, `/openapi-sync`, `/test-coverage`, `/commit` |
| Plan 2 | `/new-api-route`, `/test-py`, `/test-fe`, `/lint`, `/lint-py`, `/lint-fe`, `/commit`, `/commit-py`, `/commit-fe` |
| Plan 3 | `/new-api-route`, `/test-py`, `/test-fe`, `/docker-compose`, `/commit`, `/commit-py`, `/commit-fe` |
| Plan 4 | `/new-api-route`, `/test-py`, `/test-fe`, `/sec-review`, `/sec-py`, `/commit`, `/commit-py`, `/commit-fe` |
| Plan 5 | `/new-api-route`, `/new-opengrep-rule`, `/test-py`, `/test-fe`, `/sec-py`, `/commit`, `/commit-py`, `/commit-fe` |
| Plan 6 | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/a11y-fe`, `/build-fe`, `/commit-fe` |
| Plan 7 | `/test-py`, `/test-fe`, `/e2e-test`, `/benchmark`, `/load-test`, `/commit` |
| Cross-cutting | `/sec-review`, `/sec-py`, `/sec-fe`, `/dep-audit`, `/openapi-sync`, `/doc`, `/e2e-test` |

---

## Agent Architecture

```
Orchestrator (this session)
├── Plan 1 Agent (foundation) — sequential, blocks others
├── Plan 2 Agent (finding workflow) ─┐
├── Plan 3 Agent (scan lifecycle)  ──┤ parallel after Plan 1
├── Plan 4 Agent (user & auth)    ──┤
├── Plan 5 Agent (admin & config) ──┤
├── Plan 6 Agent (navigation & UX)──┘
├── Plan 7 Agent (portfolio) — after Plans 2, 3
├── Security Review Agent — after all plans
├── E2E Integration Agent — after all plans
└── Doc Update Agent — after all plans
```

Each plan agent:
1. Gets the full plan document + codebase patterns
2. Executes tasks sequentially within the plan (TDD: test → implement → verify → commit)
3. Reports back to orchestrator on completion
4. Orchestrator reviews before marking complete

---

## Acceptance Criteria

- [ ] All 93 audit items resolved per decision column in UX-AUDIT-FINDINGS.md
- [ ] All new endpoints documented in OpenAPI spec
- [ ] Backend test coverage ≥ 85% on new code
- [ ] Frontend test coverage ≥ 80% on new code
- [ ] All pages pass axe-core WCAG 2.1 AA scan
- [ ] API p95 latency < 200ms for paginated list endpoints (100 concurrent users)
- [ ] Frontend bundle size < 500KB gzipped
- [ ] All themes render correctly (3 themes × all new pages)
- [ ] Zero high/critical findings from security scans
- [ ] E2E multi-role user journey passes end-to-end
- [ ] RBAC matrix test: no unauthorized access across all 7 roles × all new endpoints
