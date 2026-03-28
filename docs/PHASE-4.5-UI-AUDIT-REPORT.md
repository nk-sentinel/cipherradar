# Phase 4.5 — Comprehensive UI Audit Report

> **Date:** 2026-03-28
> **Method:** Automated Playwright crawl + 4 parallel code analysis agents against D1-D32 requirements
> **Scope:** 20 pages, 250+ checkpoints, source code review

---

## Executive Summary

| Category | Count |
|---|---|
| **CRITICAL** — broken, missing, or security gap | 18 |
| **HIGH** — named deliverable missing or wrong | 22 |
| **MEDIUM** — partial implementation or inconsistency | 14 |
| **LOW** — polish, naming, minor UX | 8 |
| **PASS** — implemented correctly | ~180 |
| **Total checkpoints** | ~250 |

**Implementation rate:** ~72% of D1-D32 requirements are correctly implemented. 28% have gaps ranging from critical (security/RBAC holes) to cosmetic (naming inconsistencies).

---

## CRITICAL Issues (Fix Before Release)

### C1: Dashboard "+ New Scan" still calls browser `prompt()` (D1 #1)
- `PortfolioDashboard.tsx:120` — `prompt('Enter project ID to scan:')` instead of opening `ScanModal`
- The ScanModal component exists and works from RepoOverview, but is NOT wired to the dashboard button
- **This is the #1 audit finding that Phase 4.5 was created to fix**

### C2: Repo row "Scan" button bypasses modal (D1 #2)
- `Repositories.tsx:158` — calls `triggerScan.mutate(repo.id)` directly, not opening ScanModal
- D1 requires context-aware modal with pre-filled project

### C3: RequestQueue has NO RBAC guard (D15 security hole)
- `RequestQueue.tsx` — any authenticated user can view and approve/reject FP/RA requests
- D15: only OA, SM, SE (SE scoped to group), TM (own group) should see the queue
- **Security vulnerability — DEV/Guest can approve risk acceptance**

### C4: Bulk FP/RA fires without mandatory justification (D14, D19)
- `BulkActionBar.tsx` — `mark_fp` and `mark_ra` actions call API with no justification modal
- D14 requires structured justification for every RA/FP transition

### C5: Delete user fires without confirmation dialog (D9)
- `UserManagement.tsx` — `deleteUser.mutate(u.id)` fires on click, no name-typing confirmation
- D9 requires two-step: type user's name to confirm irreversible deletion

### C6: No status change control on FindingDetail (D14)
- `FindingDetail.tsx` — shows status as static badge, no dropdown/button to change status
- D14 defines a full lifecycle with RBAC-gated transitions, but there's no UI to invoke them from the detail page

### C7: No "Request FP/RA" buttons on FindingDetail (D15)
- `FindingDetail.tsx` — no entry point for the D15 request workflow from the main finding view
- The RequestModal component exists but has no trigger on the detail page

### C8: Migration page still exists as Kanban — D23 explicitly REJECTED this (D23 #49)
- Route `/migration`, sidebar "Migration Board", H1 "Migration Kanban" all still active
- D23 says: REJECT Kanban → replace with PQC Migration Progress section in Portfolio Compliance

### C9: Two certificate pages exist — D23 says replace, not duplicate (D23 #48)
- `/certificates` (Calendar) AND `/certificate-tracker` (Tracker) both in sidebar
- D23: rename CertCalendar to "Certificate Tracker" — one page, not two

### C10: "Asset Explorer" H1 conflicts with "Findings" sidebar label (D22)
- Sidebar says "Findings", page says "Asset Explorer" — user clicks one name, sees another
- D13/D22 use "Findings" terminology

### C11: "Compliance" sidebar not renamed to "Portfolio Compliance" (D22 #45)
- Two compliance entries in sidebar with no clear distinction
- D22 #45 explicitly says rename to "Portfolio Compliance"

### C12: No `:focus-visible` CSS — keyboard users have NO focus indicator (D32 #92)
- `globals.css` has no global `:focus-visible` rule for buttons, links, or nav items
- Keyboard-only users cannot see which element is focused

### C13: Crystal theme fails WCAG AA contrast (D29 #69)
- `--text-4` (#737373) on `--bg-0` (#f5f6f8) = 4.47:1 ratio, below 4.5:1 minimum
- D29 explicitly requires fixing this

### C14: Audit log page shows BLANK for non-admin roles (D28 #66)
- `RequireRole` renders nothing (no "Access Denied" message)
- Users see an empty page with no explanation

### C15: `/admin/llm-config` has NO sidebar entry (D5)
- Page exists and works but is completely undiscoverable
- No navigation path from any other page

### C16: Integration "Test Connection" button NOT rendered in PAT modal (D3)
- `PATModal` receives testConnection prop but never renders the button
- Props are prefixed with `_` (unused)

### C17: No group assignment at repo import (D3)
- `RepoPicker.handleImport()` hardcodes `groupId: null`
- D3: "Group assignment at import time"

### C18: SE missing `raise_fp_request` in bulk actions (D19)
- `BulkActionBar.tsx` ROLE_ACTIONS: SE cannot raise bulk FP request
- D19 table explicitly grants this to SE

---

## HIGH Issues (Named Deliverables Missing)

### H1: No file-grouped view toggle on findings table (D13)
### H2: No "Recent Activity" / status history on FindingDetail (D14 #32)
### H3: No comments section on FindingDetail (D14 #31)
### H4: No "Reopened" badge on reopened findings (D14)
### H5: No Detection column header tooltip (D13 #33)
### H6: Algorithm, First Seen, Confidence columns not sortable (D13 #25)
### H7: FindingDetail still shows "Pass N" instead of "Pattern"/"Taint" (D13 #33)
### H8: No role change confirmation dialog with impact summary (D9)
### H9: No last-OA protection check in UI for disable/demote (D9)
### H10: No Rerun button on scan queue rows (D20 #40)
### H11: No project filter on scan queue (D20 #38)
### H12: No environment badge/provenance/promote on scan rows (D21)
### H13: No customizable labels UI in OrgSettings (D4)
### H14: "Repositories" H1 should be "Projects" per D4 default
### H15: Admin > API Keys org-wide view missing (D7)
### H16: Guest role not blocked from creating API keys (D7)
### H17: Settings button on RepoOverview still routes to /admin/settings, not project settings (D8 #15)
### H18: No Re-sync button on integrations page (D3)
### H19: No "New Project" flow for vendor/non-git projects (D3)
### H20: Profile page has no visible password change form or API key buttons in production build
### H21: OnboardingWizard has no OA/SM role guard (D24 #51)
### H22: 5 extra per-repo tabs beyond D22's 6-tab model (runtime, agility, hndl-risk, cve-correlation, quantum)

---

## MEDIUM Issues

### M1: Sidebar has 19 items — Portfolio section has 8 (should be ~4 after consolidation)
### M2: `/scans` route guarded with 'repos' RBAC key, no dedicated 'scans' key
### M3: Webhook export for SIEM (Splunk/Sentinel) not implemented (D28)
### M4: Audit log user filter dropdown is hardcoded, not from API (D28)
### M5: StaleScanBanner default threshold is 14 days, spec says 30 (D20 #37)
### M6: Weekly schedule preset has no day-of-week picker (D20 #39)
### M7: Sidebar responsive collapse at 1100px not 1024px, no full collapse (D29 #70-72)
### M8: Theme preview thumbnails not implemented (D29 #75)
### M9: Breadcrumbs only work on repo-scoped routes, empty on top-level pages (D22 #42)
### M10: Hook rules violation in Breadcrumbs.tsx — conditional useRepository() call
### M11: No Jira issue link column in findings table (D18)
### M12: AccessibleTable keyboard nav exists but not used in ScanQueue/AuditLog (D32)
### M13: ShortcutsModal focus trap is partial — Tab doesn't cycle within modal (D32 #93)
### M14: "Member Since" date still hardcoded on Profile page (D30 #79)

---

## LOW Issues

### L1: "Cert Tracker" sidebar label abbreviated vs "Certificate Tracker" in D23
### L2: "Scan Queue" H1 vs "Scans" sidebar label (minor)
### L3: Compliance dashboard badges use "overdue"/"upcoming" — different from D14 status vocabulary
### L4: Projects page shows 0 findings badges — mock data not wired
### L5: Scan queue shows only "completed" status — no variety in mock data
### L6: Scan queue RBAC page key is 'repos' — should be 'scans'
### L7: `/admin/registries` shares RBAC key with org settings
### L8: SE role's view-only enforcement on PolicyRules needs source verification

---

## Pages That PASS All Requirements

| Page | Status |
|---|---|
| Login (SSO hidden, forgot password, generic error) | PASS (D8, D30) |
| Scan Queue (table, filters, pagination) | PASS with gaps (D20) |
| User Management (table, search, pagination, roles, disable) | PASS with gaps (D9-D11) |
| Policy Rules (metrics, lock, search, upload, time window) | PASS (D16, D26, D27) |
| Pending Requests (table, approve, reject, pagination) | PASS with RBAC gap (D15) |
| Artifact Registries (table, add modal, test connection) | PASS (D2) |
| LLM Config (provider selection, privacy, test connection) | PASS (D5) |
| Toast System (global, success/error variants) | PASS (D25) |

---

## Recommended Fix Priority

**Wave 1 — Security + Critical UX (blocks release):**
C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11

**Wave 2 — Named deliverables (gaps in committed scope):**
C15, C16, C17, C18, H1-H7, H10-H13

**Wave 3 — Consistency + Polish:**
H14-H22, M1-M14, L1-L8
