# CipherRadar Frontend — UX/UI Audit Findings

> **Version:** v1 | **Date:** 2026-03-22
> **Status:** REVIEW — Pending user review before planning
> **Purpose:** Consolidated list of all UX/UI issues found across 3 audit passes.
> **Action Required:** Mark each item as ACCEPT (will fix), REJECT (won't fix), DEFER (later), or ALREADY DONE.

---

## How to Use This Document

For each finding, update the **Decision** column:
- `ACCEPT` — Include in fix plan
- `REJECT` — Won't fix (add reason)
- `DEFER` — Not now, revisit later (specify when)
- `DONE` — Already implemented / audit was wrong
- `DISABLE` — Feature should be hidden/removed, not implemented

---

## Section 1: Broken Interactions (alerts, prompts, dead buttons)

These are UI elements that exist but behave poorly when clicked.

| # | Page | Element | Current Behavior | Proposed Fix | Severity | Decision |
|---|---|---|---|---|---|---|
| 1 | PortfolioDashboard | "+ New Scan" button | Browser `prompt()` asks for project ID | Modal with repo selector dropdown | CRITICAL | ACCEPT (D1) |
| 2 | RepoOverview | "Scan Now" button | Browser `alert()` stub message | Call scan API (hook exists: `useTriggerScan`) | CRITICAL | ACCEPT (D1) |
| 3 | IntegrationManagement | Git provider "Connect" buttons (x3) | Browser `alert()` about OAuth | PAT/token modal per provider (D3) | CRITICAL | ACCEPT (D3) |
| 4 | IntegrationManagement | Collab tools "Connect" buttons (x2) | Browser `alert()` about OAuth | PAT/token modal for Jira & Teams (D3) | CRITICAL | ACCEPT (D3) |
| 5 | FindingDetail | "Get Fix" button | No backend wired | Wire to LLM remediation API with consent flow | CRITICAL | ACCEPT (D5) |
| 6 | FindingRemediation | "Apply Fix" button | Browser `alert()` about future PR | Disable + inline "Copy the fix above" message | MAJOR | ACCEPT (D5) |
| 7 | Profile | Password change fields | Two inputs but NO Save button | Add "Change Password" button with validation | CRITICAL | ACCEPT (D6) |
| 8 | Profile | "Enable MFA" button | Browser `alert()` stub | Disabled button + tooltip "Available in Phase 6" | MAJOR | DEFER (D6→Phase 6) |
| 9 | Profile | "+ Create API Key" button | Browser `alert()` stub | Modal form: name, scopes, expiry → show generated key | MAJOR | ACCEPT (D7) |
| 10 | Profile | API keys table | Hardcoded mock row, no delete/revoke | Full CRUD: create, view, copy, revoke, delete | MAJOR | ACCEPT (D7) |
| 11 | AvatarDropdown | "Keyboard Shortcuts" | Browser `alert()` with text | Styled modal with shortcut reference table | MAJOR | ACCEPT |
| 12 | NotificationPrefs | Jira "Configure" button | Browser `alert()` redirect message | Navigate to IntegrationManagement Jira config (D3) | MINOR | ACCEPT (D3) |
| 13 | Login | "GitHub SSO" button | Browser `alert()` "not configured" | Hide entirely until Phase 6 SSO | MAJOR | DISABLE (D6→Phase 6) |
| 14 | Login | "SAML SSO" button | Browser `alert()` "not configured" | Hide entirely until Phase 6 SSO | MAJOR | DISABLE (D6→Phase 6) |
| 15 | RepoOverview | "Settings" button | Navigates to org settings | Navigate to project settings page (view-only for DEV/TM) | MAJOR | ACCEPT (D8) |
| 16 | RepoQuantum | "Export PQC Report" button | Disabled with "Coming soon" tooltip | Wire to existing report logic scoped to project | MINOR | ACCEPT |
| 17 | RepoCompliance | "Download Gap Report" button | Disabled with "Coming soon" tooltip | Wire to existing report logic scoped to project | MINOR | ACCEPT |

---

## Section 2: User Management Gaps

| # | Page | Missing Feature | Detail | Severity | Decision |
|---|---|---|---|---|---|
| 18 | UserManagement | Cannot edit existing user role | No role change dropdown/save on user rows | CRITICAL | ACCEPT (D9) |
| 19 | UserManagement | Cannot disable/delete user | No disable or remove action on user rows | CRITICAL | ACCEPT (D9) |
| 20 | UserManagement | No direct add (invite only) | Only invite flow exists; no "add without invite" option | MAJOR | ACCEPT (D10) |
| 21 | UserManagement | No bulk import | Cannot upload CSV of users | MINOR | DEFER (D10→CLI bridge, Phase 6 SCIM) |
| 22 | UserManagement | No pagination | Will break with 500+ users | MAJOR | ACCEPT (D11) |
| 23 | UserManagement | Role dropdown unrestricted | Non-admin can invite as org-admin (should be restricted) | MAJOR | ACCEPT (D10) |
| 24 | UserManagement | No user activity view | Cannot see last login, active sessions | MINOR | ACCEPT (D11) — Last Active column + stale indicators |

---

## Section 3: Finding & Remediation Workflow

| # | Page | Missing Feature | Detail | Severity | Decision |
|---|---|---|---|---|---|
| 25 | RepoFindings | No sorting | Cannot sort by severity, file, date | MAJOR | ACCEPT (D13) |
| 26 | RepoFindings | No pagination | Breaks with 1000+ findings | MAJOR | ACCEPT (D13) |
| 27 | RepoFindings | No bulk actions | Cannot select multiple and suppress/assign/close | MAJOR | ACCEPT (D19) |
| 28 | RepoFindings | No suppress/accept risk | No way to mark finding as false positive or accepted | MAJOR | ACCEPT (D14, D15) |
| 29 | RepoFindings | No assign to developer | Cannot assign finding ownership | MAJOR | ACCEPT (D17) |
| 30 | RepoFindings | No "create Jira issue" | Cannot create external ticket from finding | MAJOR | ACCEPT (D18) |
| 31 | RepoFindings | No finding comments | Cannot discuss findings in-app | MINOR | ACCEPT (D14) |
| 32 | RepoFindings | No finding history | Cannot see if finding existed in prior scans | MINOR | ACCEPT (D14) |
| 33 | RepoFindings | "Pass" column unclear | No tooltip explaining what Pass 1/2/3 means | MINOR | ACCEPT (D13) — rename to "Detection" |
| 34 | FindingDetail | No code syntax highlighting | Monospace only, no language-aware coloring | MINOR | ACCEPT — Shiki/Prism, theme-aware |
| 35 | FindingDetail | Hardcoded remediation text | Should be AI-generated, shows static suggestion | MAJOR | ACCEPT (D5) |

---

## Section 4: Scan Management

| # | Page | Missing Feature | Detail | Severity | Decision |
|---|---|---|---|---|---|
| 36 | RepoOverview | No scan progress feedback | "Scanning..." state never resolves | MAJOR | ACCEPT (D20) |
| 37 | RepoOverview | No stale scan warning | No alert when last scan > 30 days ago | MINOR | ACCEPT (D20) |
| 38 | Global | No scan queue/status view | Cannot see pending, running, completed scans | MAJOR | ACCEPT (D20) |
| 39 | Global | No scan scheduling | Cannot set daily/weekly automatic scans | MAJOR | ACCEPT (D20, D21) |
| 40 | RepoScans | No scan rerun | Cannot rerun a specific historical scan | MINOR | ACCEPT (D20) |

---

## Section 5: Navigation & Information Architecture

| # | Page | Issue | Detail | Severity | Decision |
|---|---|---|---|---|---|
| 41 | RepoLayout | 10 sub-tabs overwhelming | Too many tabs; group into sections or use dropdown | MAJOR | ACCEPT (D22) — consolidate to 6 tabs |
| 42 | Global | No breadcrumbs | Cannot orient within hierarchy (Dashboard > Repo > Finding) | MAJOR | ACCEPT (D22) |
| 43 | Global | No global search | Ctrl+K mentioned in shortcuts but not implemented | MAJOR | ACCEPT (D22) — project + finding search only |
| 44 | Global | No back button/navigation | Hard to return to previous page | MINOR | ACCEPT (D22) — breadcrumbs solve this |
| 45 | Compliance | Two "Compliance" pages | Portfolio > Compliance vs Compliance Dashboard — confusing naming | MAJOR | ACCEPT (D22) — rename portfolio level |
| 46 | Sidebar | Icons are Unicode not SVGs | Hard to recognize, inconsistent rendering | MINOR | ACCEPT (D22) — Lucide icons |
| 47 | TopBar | No notification bell | Notifications only in sidebar, not visible globally | MINOR | ACCEPT (D22) |

---

## Section 6: Empty/Placeholder Pages

| # | Page | Issue | Severity | Decision |
|---|---|---|---|---|
| 48 | CertCalendar | Entire page not implemented | MAJOR | ACCEPT (D23) — "Certificate Tracker" under Portfolio |
| 49 | MigrationKanban | Entire page not implemented | MAJOR | REJECT Kanban → ACCEPT as PQC Migration Progress section in Portfolio Compliance (D23) |
| 50 | Router catch-all | Generic "page not found" for undefined repo tabs | MINOR | ACCEPT (D23) |

---

## Section 7: Onboarding & Empty States

| # | Context | Missing | Severity | Decision |
|---|---|---|---|---|
| 51 | First login | No welcome/onboarding flow | MAJOR | ACCEPT (D24) — 3-step wizard for OA/SM |
| 52 | Repositories (empty) | No "Add your first repo" guidance | MAJOR | ACCEPT (D24) |
| 53 | Findings (empty filter) | No "No findings match" message with reset | MINOR | ACCEPT (D24) |
| 54 | Scans (none) | No "Run your first scan" prompt | MINOR | ACCEPT (D24) |
| 55 | Guest role | No explanation of view-only restrictions | MINOR | ACCEPT (D24) |

---

## Section 8: Admin & Settings

| # | Page | Missing Feature | Detail | Severity | Decision |
|---|---|---|---|---|---|
| 56 | OrgSettings | No save confirmation | Button grays out but no toast/feedback | MAJOR | ACCEPT (D25) — global toast system |
| 57 | OrgSettings | No per-repo policy override | All repos follow org-level config | MAJOR | ACCEPT (D26) — cascading policy with lock |
| 58 | OrgSettings | Plan field read-only | No upgrade/change path | MINOR | REJECT (D25) — remove dead UI |
| 59 | PolicyRules | Cannot create custom rules | Only enable/disable existing | MAJOR | ACCEPT (D27) — custom rules with auto-sync |
| 60 | PolicyRules | No rule search | Hard to find rules in long list | MINOR | ACCEPT (D27) — filter bar |
| 61 | PolicyRules | Enable/disable no save feedback | No confirmation that rule state persisted | MINOR | ACCEPT (D25) — global toast system |
| 62 | AuditLog | No date range filter | Cannot scope to time window | MAJOR | ACCEPT (D28) |
| 63 | AuditLog | No user filter | Cannot filter by actor | MAJOR | ACCEPT (D28) |
| 64 | AuditLog | No CSV export | Cannot export for external reporting | MAJOR | ACCEPT (D28) — CSV + webhook export |
| 65 | AuditLog | No pagination | Breaks with 10k+ entries | MAJOR | ACCEPT (D28) |
| 66 | AuditLog | RBAC inconsistency | RequireRole includes security-manager but PAGE_ACCESS doesn't | MINOR | ACCEPT (D28) — SM + CA full, SE group-scoped |

---

## Section 9: Visual & Theme Issues

| # | Component | Issue | Severity | Decision |
|---|---|---|---|---|
| 67 | DependencyGraph | Colors hardcoded, don't adapt to themes | CRITICAL | ACCEPT (D29) — move to CSS variables |
| 68 | ComplianceDashboard | FRAMEWORK_COLORS are hardcoded hex | MAJOR | ACCEPT (D29) — move to CSS variables |
| 69 | Crystal theme | --text-4 on --bg-0 fails WCAG AA contrast | MAJOR | ACCEPT (D29) — fix contrast ratio |
| 70 | Global | Grid layouts have no responsive breakpoints | MAJOR | ACCEPT (D29) — ≥1024px, mobile deferred |
| 71 | Global | Tables don't scroll on mobile | MAJOR | ACCEPT (D29) — horizontal scroll |
| 72 | Global | Sidebar doesn't collapse on mobile | MAJOR | ACCEPT (D29) — collapse at 1024px |
| 73 | Global | Badge styles mixed (classes vs inline) | MINOR | ACCEPT (D29) — standardize to classes |
| 74 | Global | Font size hierarchy inconsistent (11px-56px) | MINOR | ACCEPT (D29) — define type scale |
| 75 | Profile | Theme picker shows colored dots, no preview | MINOR | ACCEPT (D29) — thumbnail previews |

---

## Section 10: Login & Authentication

| # | Page | Issue | Severity | Decision |
|---|---|---|---|---|
| 76 | Login | No "Forgot Password" link | MAJOR | ACCEPT (D30) — reset link or contact admin |
| 77 | Login | No sign-up flow for new orgs | MINOR | REJECT (D30) — enterprise, orgs are provisioned |
| 78 | Login | Error doesn't distinguish wrong email vs wrong password | MINOR | REJECT (D30) — intentional, prevents account enumeration |
| 79 | Profile | "Member Since" date hardcoded for all users | MINOR | ACCEPT (D30) — use created_at |
| 80 | Profile | No "Change Email" option | MINOR | ACCEPT (D30) — admin-only, self-service in Phase 6 |
| 81 | Profile | No session management (view/revoke devices) | MINOR | DEFER (D30→Phase 6) |

---

## Section 11: Notifications & Integrations

| # | Page | Missing Feature | Severity | Decision |
|---|---|---|---|---|
| 82 | NotificationPrefs | No Slack integration | MAJOR | DEFER (D31) |
| 83 | NotificationPrefs | No webhook test button | MINOR | ACCEPT (D31) |
| 84 | NotificationPrefs | No quiet hours/DND config | MINOR | DEFER (D31) |
| 85 | IntegrationMgmt | No synced repos indicator per provider | MAJOR | ACCEPT (D31) |
| 86 | IntegrationMgmt | No token rotation/revoke | MAJOR | ACCEPT (D31) |

---

## Section 12: Accessibility

| # | Area | Issue | Severity | Decision |
|---|---|---|---|---|
| 87 | Keyboard | No keyboard navigation for tables, sidebar, filters | MAJOR | ACCEPT (D32) |
| 88 | Keyboard | Shortcuts mentioned in UI but not implemented | MAJOR | ACCEPT (D32) — covered by D8 |
| 89 | Screen reader | Tables missing scope attributes | MINOR | ACCEPT (D32) |
| 90 | Screen reader | Graph canvas not accessible | MINOR | ACCEPT (D32) — summary + table alt view + visual legend |
| 91 | Screen reader | Icon-only buttons missing aria-labels | MINOR | ACCEPT (D32) |
| 92 | Focus | No visible focus states on filter buttons | MINOR | ACCEPT (D32) |
| 93 | Focus | No focus trap in detail panels/modals | MINOR | ACCEPT (D32) |

---

## Totals

| Severity | Count |
|---|---|
| CRITICAL | 9 |
| MAJOR | 47 |
| MINOR | 37 |
| **Total** | **93** |

> **Note:** This is the deduplicated total across all 3 audit passes.
> Previous 13 issues from pass 3 are included and merged into this list (items 1-12, 15-17, 29, etc.)

---

## Change Log

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-22 | Initial consolidated audit from 3 passes |
