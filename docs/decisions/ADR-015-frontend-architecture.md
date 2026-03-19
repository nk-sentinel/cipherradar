# ADR-015: Frontend Architecture — React 19, TanStack, Theme System

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-19 |
| **Deciders** | Architecture session |

---

## Context

The frontend is a data-heavy security dashboard that must support 3 visual themes, 7-role RBAC with conditional navigation and route guards, real-time scan status updates, and complex data visualizations (compliance matrices, dependency graphs, trend charts). The architecture must be maintainable by a small team, type-safe end-to-end, and support development with mock APIs before the backend is ready.

---

## Decisions

### 1. Core Stack

| Layer | Choice | Rationale |
|---|---|---|
| **Framework** | React 19 + TypeScript (strict mode) | Mature ecosystem; strict mode catches type errors at compile time |
| **Build tool** | Vite | Fast HMR; native ESM; simpler config than webpack |
| **Routing** | TanStack Router | Type-safe route params and search params; file-based route generation |
| **Server state** | TanStack Query (React Query) | Declarative cache management; loading/error states built in; no `useState` + `useEffect` fetch patterns |
| **UI components** | shadcn/ui + Tailwind CSS | Full component ownership (copy-paste, not npm dependency); accessible by default; no vendor lock-in |
| **Charting** | Recharts (standard charts) | Composable React components; sufficient for bar/line/pie/area charts |
| **Graph visualization** | D3.js (Phase 3) | Required for interactive dependency graph — Recharts cannot handle force-directed layouts |

### 2. Theme System — CSS Custom Properties

Three themes ship at launch:

| Theme | Description |
|---|---|
| **Radar** | Dark theme — primary dashboard experience |
| **Crystal** | Light theme — high-contrast for readability |
| **Sentinel** | Blue-tinted dark theme — alternative dark option |

Implementation:

- Themes are defined as **CSS custom property sets** applied to the `<body>` element via a data attribute (e.g., `data-theme="radar"`)
- All component styles reference CSS variables (`var(--color-primary)`, `var(--color-surface)`, etc.) — never hardcoded color values
- Theme preference is stored in the user's profile via the API and applied on page load
- **No conditional rendering per theme** — components are built once; themes are CSS variable swaps only
- Theme switching is zero-runtime-cost (CSS variable reassignment, no React re-render tree)

### 3. RBAC in the UI

- **Route guards**: a wrapper component checks the user's role against the route's required permissions before rendering the page. Unauthorized access returns a 403 page and redirects to the user's default landing page.
- **Sidebar navigation**: items are conditionally rendered based on the user's role permissions. Users only see navigation items for pages they can access.
- **Component-level guards**: action buttons (e.g., "Trigger Scan", "Edit Policy") are hidden or disabled based on role permissions. The backend enforces permissions independently — UI guards are a UX convenience, not a security boundary.

### 4. Mock API — MSW (Mock Service Worker)

Development milestones C-M1 and C-M2 use **MSW** to intercept API calls and return mock responses matching the OpenAPI spec. This allows frontend development to proceed in parallel with backend development. Real API integration happens at C-M3 only.

MSW handlers are co-located with the features they mock and are excluded from production builds.

### 5. API Client — Auto-Generated Types

TypeScript types for all API request/response models are **auto-generated from the backend's OpenAPI spec** using `openapi-typescript`. No hand-written API types are permitted — the generated types are the single source of truth for the frontend/backend contract.

The generation step runs as part of the build pipeline and during development via a watch command. Type mismatches between frontend and backend are caught at compile time.

---

## Rationale

### TanStack Query over manual fetching
Data-heavy dashboards suffer from stale data, race conditions, and inconsistent loading states when using raw `useEffect` + `fetch`. TanStack Query provides automatic cache invalidation, background refetching, optimistic updates, and declarative loading/error handling — eliminating an entire class of bugs.

### shadcn/ui over component libraries
Traditional component libraries (Material UI, Ant Design, Chakra) are npm dependencies with opinionated styling, upgrade churn, and limited customization. shadcn/ui is a copy-paste model — components are copied into the project source and owned entirely by the team. This eliminates vendor lock-in, makes theme customization straightforward, and avoids breaking changes from upstream library updates.

### CSS variable theming
Runtime theme engines (CSS-in-JS, context-based style objects) add JavaScript overhead and cause React re-renders on theme switch. CSS custom properties are resolved by the browser's style engine with zero JavaScript cost. The `data-theme` attribute swap triggers a CSS recalculation only — no component re-rendering.

### Auto-generated API types
Hand-written API types drift from the backend over time, causing runtime errors that TypeScript cannot catch. Auto-generation from the OpenAPI spec guarantees compile-time alignment. When the backend changes a response shape, the frontend build fails immediately — before the code reaches production.

---

## Consequences

- **Positive:** TanStack Query eliminates stale-data bugs and provides consistent loading/error states across the dashboard
- **Positive:** shadcn/ui gives full component ownership — no black-box library dependencies or upgrade churn
- **Positive:** CSS variable theming is zero-runtime-cost and does not trigger React re-renders
- **Positive:** Auto-generated API types guarantee frontend/backend contract alignment at compile time
- **Positive:** MSW enables frontend development to proceed in parallel with backend, unblocked
- **Negative:** TanStack Router has a smaller community than React Router — fewer third-party examples and Stack Overflow answers
- **Negative:** 3 themes increase QA surface area — every UI component must be visually verified in all 3 themes

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/12-phase2-implementation-plan.md` | C-M1 milestone: frontend architecture and tooling scope defined |
