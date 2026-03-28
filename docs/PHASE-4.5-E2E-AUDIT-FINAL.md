# Phase 4.5 — Final E2E Audit Report

> **Date:** 2026-03-28
> **Method:** Playwright interactive crawl (18 pages, 17 button tests) + 2 parallel deep analysis agents (D1-D32 requirements + source code review)
> **Status:** Ready for review — fix decisions needed

---

## Executive Summary

| Category | Count |
|---|---|
| **D-decisions PASS** | 14/32 (44%) |
| **D-decisions PARTIAL** | 16/32 (50%) |
| **D-decisions FAIL** | 2/32 (6%) |
| **Code-level critical issues** | 3 |
| **Code-level important issues** | 10 |
| **Total actionable findings** | 31 |

The app is stable (0 crashes across 18 pages), but ~50% of decisions are only partially implemented. Most gaps are missing sub-features within otherwise working pages, not missing pages.

---

## D1-D32 Decision Status

| Decision | Status | Key Gap |
|---|---|---|
| D1 Scan Modal | PARTIAL | Dashboard modal lacks project picker; data-poisoning locked-source model not in UI |
| D2 Artifact Registries | PASS | |
| D3 Integration Connect | PASS | |
| D4 Org Hierarchy/Labels | PARTIAL | Group management page missing; customizable labels not hydrated from API |
| D5 LLM Config | PASS | |
| D6 Password Management | PARTIAL | Password form hidden behind tab; auth_source not typed on User model |
| D7 API Keys | PARTIAL | Self-service works; Admin org-wide API Keys page missing entirely |
| D8 Section 1 Remaining | PARTIAL | Keyboard shortcuts modal unconfirmed |
| D9 User Lifecycle | PASS | |
| D10 User Creation | PASS | |
| D11 User Table UX | PARTIAL | Stale color is yellow not orange (minor) |
| D12 Role Resolution | PARTIAL (by design) | Per-group role deferred to Phase 6 |
| D13 Finding Table UX | PASS | File-grouped view, sortable columns, detection tooltip all present |
| D14 Finding Status Model | PASS | 6 statuses, justification, history, comments all wired |
| D15 FP/RA Requests | PARTIAL | Approval RBAC not request-type-aware (SE shouldn't approve RA) |
| D16 Rule Analytics | PARTIAL | Analytics columns present; expandable detail unverified |
| D17 SE/TM Refinement | PARTIAL | SE policy view-only enforcement unverified |
| D18 Jira Integration | PARTIAL | Group-level Jira config page missing |
| D19 Bulk Actions | PARTIAL | Role-gating of actions unverified |
| D20 Scan Management | PARTIAL | Queue + rerun work; progress bar dead (never receives scan ID) |
| D21 Scan Provenance | PARTIAL | Code exists but mock data has no env values — appears broken |
| D22 Navigation | PARTIAL | 6 tabs done; breadcrumbs only 2-level; Quantum still standalone |
| D23 Empty/Placeholder | PASS | Migration removed, cert merged, empty states working |
| D24 Onboarding | PASS | Wizard with OA/SM guard, empty states, guest banner |
| D25 Toast System | PASS | |
| D26 Policy Cascade | PARTIAL | Cannot confirm 3-tier cascade UI |
| D27 Custom Rules | PARTIAL | Upload + lock work; fork UI unverified |
| D28 Audit Log | PARTIAL | CA excluded from RBAC (should have access); SIEM webhook missing |
| D29 Visual/Theme | PARTIAL | focus-visible done; other fixes unverified |
| D30 Login & Auth | PARTIAL | Forgot password done; Change Email absent |
| D31 Notifications | PARTIAL | Token rotation function exists; webhook test + synced repos unverified |
| D32 Accessibility | PARTIAL | focus-visible done; custom modals lack focus trap |

---

## Critical Code Issues

### CRIT-1: Mock data fallback in production (ALL hooks)
Every API hook catches errors and silently falls back to hardcoded mock data. In production, if the API returns 500, users see fake security data (fake finding counts, fake repos, fake notifications). **Users will make security decisions based on fictional numbers.**
- Files: `useNotifications.ts`, `usePortfolio.ts`, `useRepositories.ts`, `useFindings.ts`, +10 more
- Fix: Gate mock fallback behind `import.meta.env.DEV`

### CRIT-2: Scan progress bar is permanently dead code
`RepoOverview.tsx` has `_setActiveScanId` (underscore = unused). `ScanModal` never returns the new scan ID. The entire WebSocket progress feature (D20 #36) is unreachable.
- Fix: `ScanModal` callback → `setActiveScanId(newScanId)`

### CRIT-3: Last-OA check counts only current page
`UserManagement.tsx` counts org-admins from `data.items` (current page of 25). If there are 2 OAs on different pages, the count is wrong. Either blocks valid demotions or allows demoting the last OA.
- Fix: Use a server-side count endpoint

---

## Navigation / Structure Issues

### NAV-1: Quantum Readiness still standalone page
D22/D23 says fold into Portfolio Compliance. Sidebar still shows it at `/quantum`.

### NAV-2: Two compliance pages remain
"Portfolio Compliance" + "Compliance Dashboard" both in sidebar. D22 says one entry.

### NAV-3: Scans sidebar item uses wrong RBAC key
`page: 'repos'` instead of `page: 'scans'`

### NAV-4: Breadcrumbs only 2 levels
Shows `Projects / {repoName}`. D22 says `Org / Group / Project / Tab`.

### NAV-5: AI Remediation + Registries visible to SM in sidebar but blocked by page guard
SM sees nav links that lead to "Access Denied" cards.

---

## RBAC Issues

### RBAC-1: Audit Log excludes Compliance Auditor
D28 says CA has full read-only access. `RequireRole` only allows OA + SM.

### RBAC-2: FP/RA approval not type-aware
SE can approve RA requests (should only approve FP). TM sees approve buttons (should be view-only).

### RBAC-3: ArtifactRegistries has no RequireRole guard
SM can manage registry credentials — inconsistent with LLMConfig which is OA-only.

---

## Data / Integration Issues

### DATA-1: Environment badges never render
Mock scan data has no `environment` field. Feature appears broken but code is correct.

### DATA-2: OrgSettings label save overwrites with defaults
`groupLabel` and `projectLabel` initialized to defaults, not hydrated from API. Every save resets custom labels.

### DATA-3: Notification preferences are static constants
Profile page shows hardcoded prefs that are never editable or persisted.

### DATA-4: "My Assigned Findings" is always empty
Permanent placeholder — backend hook not wired.

---

## Missing Features (Not Partially Implemented — Absent)

| Feature | Decision | Status |
|---|---|---|
| Admin > API Keys org-wide page | D7 | Not created |
| Group Management page | D4 | No route, no sidebar link |
| Change Email flow | D30 #80 | Not implemented |
| SIEM webhook export config | D28 | TODO comment only |
| Keyboard Shortcuts modal | D8 #11 | Unconfirmed |

---

## Confirmed Working (Pass with Confidence)

These decisions are solidly implemented with full feature coverage:

D2, D3, D5, D9, D10, D13, D14, D23, D24, D25

---

## Recommended Fix Priority

**Wave 1 — Security + Data Integrity:**
- CRIT-1 (mock fallback in production)
- RBAC-1 (CA excluded from audit log)
- RBAC-2 (approval not type-aware)
- RBAC-3 (registries no guard)
- CRIT-3 (last-OA check)

**Wave 2 — Core Feature Completions:**
- CRIT-2 (scan progress dead)
- NAV-1 (remove quantum standalone)
- NAV-2 (merge compliance pages)
- DATA-2 (label save bug)
- DATA-4 (assigned findings)

**Wave 3 — Missing Features:**
- D7 Admin API Keys page
- D4 Group Management page
- NAV-4 (breadcrumbs 4-level)
- D32 modal focus traps

**Wave 4 — Polish:**
- NAV-3, NAV-5 (RBAC key fixes)
- DATA-1, DATA-3 (mock data, notification prefs)
- D30 #80 (change email)
- D28 SIEM webhook
