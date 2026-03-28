# E2E Interactive Test Results — 2026-03-28

## Test Results

| Test | What | Result | Issue? |
|---|---|---|---|
| T1 | Dashboard "+ New Scan" button | `false` — button not found | FAIL — button text may have changed or component not rendering |
| T2 | Projects page H1 | `Projects` | PASS — correctly renamed from "Repositories" |
| T3 | User Management | h1=User Management, addBtn=true, roleDropdowns=8, rows=7 | PASS |
| T4 | Profile page | pwInputs=0, hasApiKey=true, hasChangePw=false, hasMFA=false, hasTheme=true | FAIL — no password inputs visible, no "Change Password" button, no MFA text |
| T5 | Policy Rules | uploadBtn=true, lockBtns=6, tables=2, timeWindow=true | PASS |
| T6 | Audit Log | hasContent=false, hasFilters=0, hasExport=false, hasTable=false | FAIL — page appears completely empty (RBAC guard rendering nothing?) |
| T7 | Pending Requests | hasTable=true, rows=1, correct headers | PASS |
| T8 | Scan Queue | filters=3, rows=18, hasRerun=true, hasEnvBadge=false | PARTIAL — rerun present but no environment badges |
| T9 | Sidebar | 20 items total | See analysis below |
| T10 | Migration removed | YES removed | PASS — D23 fix applied |
| T11 | Cert duplicates | hasCertificates=false, hasCertTracker=true | PASS — D23 fix applied |
| T12 | focus-visible CSS | true | PASS — D32 fix applied |

## Sidebar Analysis (T9)

20 sidebar items:
1. auth-api → /repos/f1f9... (project tree link)
2. Dashboard → /
3. Projects → /repos
4. Scans → /scans
5. Findings → /assets
6. Portfolio Compliance → /compliance
7. Compliance Dashboard → /compliance-dashboard
8. Quantum Readiness → /quantum
9. Dependency Graph → /graph
10. Certificate Tracker → /certificate-tracker
11. CBOM Diff → /diff
12. Org Settings → /admin/settings
13. Users → /admin/users
14. Integrations → /admin/integrations
15. Audit Log → /admin/audit-log
16. Registries → /admin/registries
17. AI Remediation → /admin/llm-config
18. Pending Requests → /requests
19. Policy Rules → /policy
20. nk-sentinel → / (org link)

## Key Findings

### FIXED from previous round (confirmed):
- Migration Board removed ✓
- Duplicate certificate page removed ✓
- "Projects" H1 (was "Repositories") ✓
- AI Remediation sidebar link added ✓
- Portfolio Compliance renamed ✓
- focus-visible CSS added ✓
- Rerun button on scan queue ✓
- 3 filters on scan queue ✓

### STILL BROKEN:
1. Dashboard "+ New Scan" not found (T1) — may be rendering issue or button text mismatch
2. Profile: no password inputs, no "Change Password" button, no MFA section (T4)
3. Audit Log: completely empty (T6) — RBAC guard still rendering blank
4. Scan queue: no environment badges (T8)
5. Still 2 compliance pages in sidebar (Portfolio Compliance + Compliance Dashboard)
6. Quantum Readiness still a separate page
