# Phase 4.5 — Plan 6: Navigation & UX — Detailed Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Navigation overhaul, onboarding, theme fixes, accessibility, visual polish.

**Decisions:** D4, D8, D22, D23, D24, D29, D31, D32

---

## Agent Assignment

| Agent | Tasks |
|---|---|
| **Frontend Nav** | 6.1, 6.2, 6.3, 6.4 |
| **Frontend UX** | 6.5, 6.6, 6.7, 6.8, 6.9, 6.10 |
| **E2E + A11y** | 6.11, 6.12 |

Frontend Nav and Frontend UX run in parallel. E2E after both.

---

## Task 6.1: Tab Consolidation (D22 #41)

Modify `frontend/src/pages/repo/RepoLayout.tsx` — reduce tabs from 10+ to 6:
- Overview, Findings, Compliance (merge quantum), Dependencies (merge SBOM), Scans, Settings (absorb config)

Modify `frontend/src/router.tsx` — update repo sub-routes.
Tests. Commit: `feat: consolidate project tabs to 6 (D22)`

## Task 6.2: Breadcrumbs (D22 #42)

Create `frontend/src/components/layout/Breadcrumbs.tsx` — `Org > Group > Project > Tab`. Clickable at each level.
Modify TopBar.tsx to include breadcrumbs.
Tests. Commit: `feat: add breadcrumbs navigation (D22)`

## Task 6.3: Global Search — Ctrl+K (D22 #43)

Create `frontend/src/components/layout/CommandPalette.tsx` — Ctrl+K opens modal, search projects + findings by name/algorithm/file. Uses GET /search endpoint.
Create `frontend/src/api/hooks/useSearch.ts`.
Tests. Commit: `feat: add Ctrl+K command palette search (D22)`

## Task 6.4: Sidebar Overhaul (D22 #46, #47, D4)

Modify `frontend/src/components/layout/Sidebar.tsx` — replace Unicode icons with Lucide React icons. Add groups with collapsible project tree. Support customizable labels from org settings (D4).
Modify TopBar — notification bell already added, verify.
Tests. Commit: `feat: overhaul sidebar with Lucide icons and project tree (D22, D4)`

## Task 6.5: Onboarding Wizard (D24 #51)

Create `frontend/src/components/onboarding/OnboardingWizard.tsx` — 3-step: connect provider → import projects → first scan. Shows on first OA/SM login. Stores completion in localStorage.
Create `frontend/src/pages/Onboarding.tsx`.
Tests. Commit: `feat: add onboarding wizard for first login (D24)`

## Task 6.6: Empty States (D24 #52-#55)

Create `frontend/src/components/ui/EmptyState.tsx` — reusable: illustration, message, action button. Per-context variants: no projects, no findings, no scans, guest info.
Apply to: Repositories page, findings page (empty filter), scans page.
Tests. Commit: `feat: add empty state components (D24)`

## Task 6.7: Theme & Visual Fixes (D29)

Modify CSS theme files — move hardcoded colors to variables (#67, #68). Fix Crystal contrast (#69). Add responsive breakpoints at 1024px (#70-#72). Standardize badges to classes (#73). Define type scale (#74). Theme preview thumbnails (#75).
Tests (visual regression via Playwright screenshot). Commit: `feat: fix themes, responsive layout, badge consistency (D29)`

## Task 6.8: Keyboard Shortcuts Modal (D8 #11)

Create `frontend/src/components/layout/ShortcutsModal.tsx` — styled modal with shortcut reference table (replaces alert). Triggered from avatar dropdown.
Tests. Commit: `feat: add keyboard shortcuts modal (D8)`

## Task 6.9: Notification & Integration Polish (D31)

Modify notification preferences page — add webhook test button (#83).
Modify integration page — synced repos indicator already done in Plan 5, verify token rotation warning (#86).
Tests. Commit: `feat: add webhook test button and token rotation warning (D31)`

## Task 6.10: Accessibility (D32)

Add keyboard navigation to tables, sidebar, filters (#87). Add `scope` attrs to table headers (#89). Add `aria-label` to icon-only buttons (#91). Add `:focus-visible` states (#92). Add focus trap to modals (#93). Graph legend with SVG shapes (#90).
Tests (axe-core per page). Commit: `feat: add accessibility improvements — keyboard nav, ARIA, focus (D32)`

## Task 6.11: E2E — Navigation & UX Tests

Create `frontend/e2e/navigation-ux.spec.ts` — breadcrumb navigation, Ctrl+K search, onboarding wizard, responsive at 1024px, theme switch.
Commit: `test: add navigation and UX E2E tests`

## Task 6.12: Accessibility — Full A11y Audit

Create `frontend/e2e/accessibility-audit.spec.ts` — axe-core scan on EVERY page (dashboard, findings, scans, profile, admin pages, login). Report violations.
Commit: `test: add full accessibility audit`
