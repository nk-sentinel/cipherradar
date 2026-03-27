# Phase 4.5 — Plan 5: Admin & Config — Detailed Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Integration management, LLM config, policy cascade, custom rules, audit log enhancements.

**Decisions:** D3, D5, D26, D27, D28

---

## Agent Assignment

| Agent | Tasks |
|---|---|
| **Backend Admin** | 5.1, 5.3, 5.5, 5.7, 5.9, 5.12 |
| **Frontend Admin** | 5.2, 5.4, 5.6, 5.8, 5.11, 5.13 |
| **CLI + E2E** | 5.10, 5.14, 5.15 |

---

## Task 5.1: Backend — Integration Management (D3)

**Create:** `backend/app/services/integration_service.py`, `backend/app/schemas/integration.py`, `backend/app/api/v1/integration_connect.py`, tests

**Service:** connect (store PAT hash + encrypted token), disconnect, test_connection (HTTP call to provider API), discover_repos (paginated repo list from provider), import_repos (create projects from selected repos).

**Routes:** POST /admin/integrations/{provider}/connect, DELETE /admin/integrations/{provider}, POST /admin/integrations/{provider}/test, GET /admin/integrations/{provider}/repos, POST /admin/integrations/import. Roles: OA, SM.

Commit: `feat: add integration management service and routes (D3)`

## Task 5.2: Frontend — Integration Management Page (D3)

**Modify:** existing `frontend/src/pages/admin/IntegrationManagement.tsx`
**Create:** connect modal per provider (PAT input, base URL, test connection), repo picker (search, select, import to group), hooks

Commit: `feat: overhaul integration management page (D3)`

## Task 5.3: Backend — LLM Configuration (D5)

**Create:** `backend/app/services/llm_config_service.py`, `backend/app/schemas/llm_config.py`, `backend/app/api/v1/llm_config.py`, tests

**Service:** get_config, save_config (provider, url, model, key, temp, max_tokens, custom instructions, privacy settings), test_connection (call provider with test prompt).

**Routes:** GET/PUT /admin/llm-config, POST /admin/llm-config/test. Roles: OA.

Commit: `feat: add LLM configuration service and routes (D5)`

## Task 5.4: Frontend — LLM Admin Page (D5)

**Create:** `frontend/src/pages/admin/LLMConfig.tsx`, hooks, tests
Provider selector (Anthropic/OpenAI/Ollama/Custom/Disabled), per-provider fields, test connection, privacy toggles, custom instructions textarea.

Commit: `feat: add LLM configuration admin page (D5)`

## Task 5.5: Backend — AI Remediation Wiring (D5)

**Create:** `backend/app/services/remediation_service.py` — wire "Get Fix" to configured LLM. Consent verification, response caching (TTL from config), privacy transforms (strip comments, anonymize vars).

**Modify:** `backend/app/api/v1/remediation.py` — expand existing stub

Commit: `feat: wire AI remediation to configured LLM provider (D5)`

## Task 5.6: Frontend — Finding Remediation UX (D5)

**Modify:** `frontend/src/components/findings/FindingDetail.tsx` — consent modal showing exact code to send, side-by-side original vs fix, copy button, provider name, confidence score.

Commit: `feat: add AI remediation consent flow and fix display (D5)`

## Task 5.7: Backend — Policy Cascade (D26)

**Create:** `backend/app/services/policy_service.py`, `backend/app/schemas/policy.py`, `backend/app/api/v1/policy.py`, tests

**Service:** resolve_policy (project→group→org with lock enforcement), save_policy (validate locks), get_effective_rules (merge overrides).

**Routes:** GET/PUT /policy (org), GET/PUT /groups/{id}/policy, GET/PUT /projects/{id}/policy. OA sets org + locks, SM overrides group/project.

Commit: `feat: add policy cascade with lock mechanism (D26)`

## Task 5.8: Frontend — Policy Configuration UI (D26)

**Modify:** `frontend/src/pages/PolicyRules.tsx` — add override indicators, severity override per rule, lock icon (OA only), scope selector.

Commit: `feat: add policy cascade UI with lock indicators (D26)`

## Task 5.9: Backend — Custom Rules (D27)

**Create:** `backend/app/services/custom_rule_service.py`, `backend/app/schemas/custom_rule.py`, `backend/app/api/v1/custom_rules.py`, tests

**Service:** upload (validate OpenGrep YAML schema), fork (clone built-in + link parent), dry_run (test against project), list (built-in + custom with filters), delta_sync (for CLI).

**Routes:** POST/GET /admin/rules, PUT/DELETE /admin/rules/{id}, POST /admin/rules/{id}/test, GET /rules/delta?since=. OA only for mutations.

Commit: `feat: add custom rules management (D27)`

## Task 5.10: CLI — Custom Rule Auto-Sync (D27)

**Modify:** `cli/internal/cmd/scan.go` — at scan start, check portal for delta rules, download to ~/.cradar/rules/, graceful fallback.

Commit: `feat: add CLI custom rule auto-sync from portal (D27)`

## Task 5.11: Frontend — Custom Rules UI (D27)

**Create:** rule upload modal, fork flow, search/filter bar on rules table.

Commit: `feat: add custom rules UI — upload, fork, search (D27)`

## Task 5.12: Backend — Audit Log Enhancements (D28)

**Modify:** `backend/app/api/v1/admin.py` — enhance audit log endpoint with filters (date range, actor, action type, project/group), CSV export, webhook forwarding.

**Create:** `backend/app/services/audit_log_query_service.py`, `backend/app/schemas/audit_log.py`, tests

Commit: `feat: enhance audit log with filters, export, webhook (D28)`

## Task 5.13: Frontend — Audit Log Page (D28)

**Modify:** `frontend/src/pages/admin/AuditLog.tsx` — date range picker, user filter, action type filter, pagination, CSV export button, webhook config section.

Commit: `feat: enhance audit log page with filters and export (D28)`

## Task 5.14: E2E — Admin Tests

**Create:** `frontend/e2e/admin-config.spec.ts` — integration connect flow, LLM config, custom rule upload, audit log filters, accessibility.

Commit: `test: add admin config E2E tests`

## Task 5.15: Security — Admin Tests

**Create:** `backend/tests/security/test_admin_security.py` — token encryption verification, LLM key not in responses, custom rule injection prevention, audit log RBAC.

Commit: `test: add admin security tests`
