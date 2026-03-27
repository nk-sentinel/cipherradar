# Phase 4.5 — UI Stabilization & UX Polish: Design Decisions

> **Version:** v1 | **Date:** 2026-03-22
> **Status:** In Progress — decisions being locked during audit review session

---

## Decision Log

### D1: New Scan Modal (#1, #2 merged)

**Status:** LOCKED

**Design:**
- 3 scan source types in one modal: Repository, Container Image, Artifact (upload or fetch from registry)
- All produce CycloneDX CBOM, land in unified findings view
- IaC scanning is NOT a separate type — fires automatically during repo scan
- Binary scanning (JAR/WAR inside repos) is automatic, not a separate type

**Scan sources per project:**
- A project has a primary type (repository / vendor-app / standalone) but supports multiple scan sources via `linked_sources` JSONB field
- Git projects can also trigger container or artifact scans if linked sources are configured
- Each scan records `scan_source_type` (source / container / artifact) and `scan_source_ref`

**Context-aware behavior:**
- Dashboard "+ New Scan": full 3-tab modal
- Repo row "Scan" button: opens modal pre-filled with that repo, source code selected
- RepoOverview "Scan Now": opens simplified modal (branch + policy), "More options" expands to full modal
- All scan sources within a project are pre-configured and locked — user only picks branch/tag/version

**Data poisoning protection:**
- Source scan: locked to project's configured git_url, user picks branch only
- Container scan: locked to project's linked container source, user picks tag only
- Artifact scan: locked to project's linked artifact source, user picks version only
- Upload: checksum + filename validation, first upload requires approval
- All scan triggers logged in audit trail

**Project model evolution:**
- Add `type` column: 'repository' | 'vendor-app' | 'standalone'
- Add `linked_sources` JSONB column for container/artifact registry references
- Backend model already uses `Project` (not Repository) with `Group` hierarchy — minimal migration needed

---

### D2: Artifact Registry Admin Page (from #1)

**Status:** LOCKED

**Design:**
- Renamed from "Container Registries" to "Artifact Registries" — supports both container images and binary artifacts
- Org-level configuration: Admin > Artifact Registries
- Supports: JFrog, ECR, GCR, ACR, Docker Hub, Harbor, GitLab, Custom
- Each registry stores: name, URL, type, auth method, credentials (encrypted), include/exclude filters
- Docker Hub (public) always available without config
- Auth methods: Token, Username+Password, AWS IAM Role, Service Account JSON
- Connection status with last-tested timestamp

---

### D3: Integration Connect — PAT/Token Auth (#3, #4)

**Status:** LOCKED

**Design:**
- Option B selected: Manual PAT/token configuration for all providers (no OAuth in Phase 4.5)
- Modal per provider with: Base URL, Token input, required scopes documentation, "Test Connection" button
- Supports GitHub, GitLab, Bitbucket, Jira, Teams
- Enterprise URL support (GitHub Enterprise, GitLab self-hosted)
- PAT covers 90% of enterprise use cases; OAuth can be added later as UX upgrade

**Repo sync after connecting:**
- NOT auto-import. Shows repo picker screen with search, language hints, last activity
- User selects which repos to import as projects
- Group assignment at import time
- Auto-scan toggle per import batch
- Already-imported repos shown as "Imported" and can't be duplicated
- Re-sync button to discover new repos added since last sync
- Background periodic check (24h) with notification for new available repos

**Non-Git projects:**
- Created manually via "New Project" flow (not via sync)
- Project type selector: "Import from Git" or "Vendor / External"
- Vendor projects configured with linked scan sources (container image, artifact registry, upload)

---

### D4: Org Hierarchy Model (#94)

**Status:** LOCKED

**Model:** Org → Group → Project (flat groups, no nesting)

| Level | What it represents | Examples |
|---|---|---|
| Org | Company | Acme Corp |
| Group | Team / department / service area | Payment Services, Identity Platform |
| Project | Anything you scan | git repo, vendor binary, container image, standalone certs |

**Key decisions:**
- Groups are organizational, not git-derived. A group can contain repos from multiple git orgs, vendor binaries, containers, etc.
- No nested groups. Flat model. Use naming for sub-hierarchy ("Payments - Backend", "Payments - Mobile").
- Multi-org deferred — single org per deployment for now.

**Customizable labels (org-level setting):**

| Default | Can be renamed to |
|---|---|
| Group | Department, Team, Business Unit, Division |
| Project | Application, Service, Repository, Component |

Label changes only — no data model impact. Applies across all UI text.

---

### D5: AI Remediation — LLM Configuration & UX (#5, #6, #35)

**Status:** LOCKED

**Frontend wiring:**
- "Get Fix" button on FindingDetail opens consent modal showing exact code that will be sent
- User must check consent checkbox before "Generate Fix" is enabled
- After generation: shows side-by-side original vs fixed code, explanation, confidence score, provider name
- Cached results returned instantly (no re-call to LLM)
- "Copy Fix" button for manual application; auto-PR deferred to later phase
- "Apply Fix" button (#6) replaced with disabled state + inline "Copy the fix above" message

**Admin UI — LLM Configuration (new page: Admin > AI Remediation):**
- Provider selector: Anthropic, OpenAI, Ollama, Custom (OpenAI-compatible), Disabled
- Per-provider fields: URL, API key/token, model selector
- Custom provider: API URL + auth header + model ID + API format (OpenAI-compatible)
- Covers in-house LLM: Ollama for local, Custom for vLLM/TGI/Azure OpenAI/AWS Bedrock
- "Test Connection" button per provider
- Settings saved to DB, override env vars

**Prompt enhancements:**
- Core template unchanged (crypto expert, structured JSON response)
- New: org-level custom instructions (plain English, appended to system prompt)
  - e.g., "Always use our internal crypto wrapper com.acme.crypto"
  - e.g., "Prefer AES-256-GCM for symmetric encryption"
- New: compliance context injected (active frameworks, quantum deadline)
- New: prompt settings — temperature, max tokens (admin-configurable)

**Privacy controls (admin-configurable):**
- Require user consent before sending code (default: on, cannot be turned off)
- Strip comments before sending to LLM (optional)
- Strip/anonymise variable names (optional)
- Show code preview before sending (always on)
- Cache results with configurable TTL (default: 7 days)

---

### D6: Password Management & Auth Source Foundation (#7, #8 partial)

**Status:** LOCKED

**Password change (user self-service):**
- Local users can change their own password (current + new password form)
- Backend endpoint: `PUT /api/v1/auth/password` with current_password + new_password
- Validation: current password must match, new password meets policy (min 8 chars, complexity)
- Success: toast notification, optional force re-login
- All 7 roles can change their own password when auth_source = "local"

**Password reset (admin):**
- Org Admin can force-reset any local user's password without knowing current password
- Backend endpoint: `PUT /api/v1/admin/users/{id}/reset-password`
- Generates temporary password or sends reset link
- Logged in audit trail

**Auth source foundation:**
- Add `auth_source` field to User model: 'local' | 'saml' | 'oidc' | 'scim'
- Default: 'local' for all existing users
- Profile UI conditionally renders based on auth_source:
  - local: show password change, MFA setup
  - saml/oidc/scim: hide password & MFA, show "Managed by [IdP name]" with link to corporate portal
- Admin user management conditionally renders:
  - local: Reset Password, Change Role, Disable, Delete
  - scim: Change Role (with override warning), Disable (with sync warning). No Reset Password, no Delete.

**MFA (#8):**
- Phase 4.5: Replace alert with disabled button + tooltip "Requires SSO or will be available in Phase 6"
- Actual MFA implementation deferred to Phase 6 (tied to auth infrastructure)

**SSO/SCIM deferred to Phase 6:**
- SAML 2.0 SSO
- OIDC SSO (Okta, Azure AD)
- SCIM 2.0 provisioning
- AD group → CipherRadar role mapping

---

### D7: API Key Management (#9, #10, #13)

**Status:** LOCKED

**Self-service (Profile > My API Keys):**
- All roles except Guest can create, view, and revoke their own API keys
- Create flow: modal with name, expiry (30/60/90/180/365/Never), scope checkboxes
- Scopes available capped by user's role permissions (Developer can't create scan:write key)
- Key displayed once at creation with copy button, then only prefix shown (cr_sk_a1b2...****)
- Keys stored as hashed values (SHA-256), never reversible
- Revoke button on each key row with confirmation dialog
- Replaces hardcoded mock API key row (#13)

**Admin view (Admin > API Keys — new section):**
- Org Admin: full visibility of all org keys, can revoke any key
- Security Manager: read-only view of all org keys
- All other roles: only see own keys
- Table: name, owner, scopes, created, last used, status, actions
- Stale key warning: unused 30+ days or owner account disabled
- Export key inventory as CSV (for compliance audits)
- Filter by: owner, scope, status, date range

**Backend endpoints:**
- `POST /api/v1/auth/api-keys` — create key (returns raw key once)
- `GET /api/v1/auth/api-keys` — list user's keys (masked)
- `DELETE /api/v1/auth/api-keys/{id}` — revoke own key
- `GET /api/v1/admin/api-keys` — list all org keys (admin only)
- `DELETE /api/v1/admin/api-keys/{id}` — revoke any key (org admin only)

**Audit:** Every key creation, usage, and revocation logged in audit trail.

---

### D8: Section 1 Remaining Items (#11–#17)

**Status:** LOCKED

**#11 — Keyboard Shortcuts modal:** ACCEPT
- Replace `alert()` with styled modal showing shortcut reference table
- Actual shortcut implementation (Ctrl+K, Ctrl+B, etc.) deferred — modal is reference-only for now

**#12 — Jira Configure button:** ACCEPT per D3
- Navigate to IntegrationManagement where Jira PAT/token config lives (D3 flow)
- If user lacks admin role, show "Contact your admin" message

**#13 — GitHub SSO button (Login):** DISABLE
- Hide entirely until Phase 6 SSO implementation (D6)
- Login page should only show functional auth options

**#14 — SAML SSO button (Login):** DISABLE
- Same as #13 — hide until Phase 6

**#15 — Settings button (RepoOverview):** ACCEPT
- Navigate to project-specific settings page (not org settings)
- Page sections: General (name, type, group), Scan Sources (linked git/container/artifact from D1), Scan Config (default branch, auto-scan, schedule), Notifications (per-project channels)
- RBAC: OA + SM can edit; SE, TM, CA, DEV get read-only view; Guest no access
- Edit controls disabled with "View only — contact your admin" for read-only roles

**#16 — Export PQC Report (RepoQuantum):** ACCEPT
- Wire to existing report generation logic scoped to single project
- Backend already supports this at portfolio level; add project-level filter

**#17 — Download Gap Report (RepoCompliance):** ACCEPT
- Same pattern as #16 — wire to existing logic with project scope

---

### D9: User Lifecycle — Edit Role, Disable, Delete (#18, #19)

**Status:** LOCKED

**Role editing:**
- Inline dropdown on user row in User Management table
- Only Org Admin can change roles (per RBAC matrix)
- Confirmation dialog showing old role → new role with impact summary
- **Downgrade handling:** API keys whose scopes exceed the new role's cap are auto-revoked with notification to the user
- **Self-demotion protection:** Cannot demote the last Org Admin — system enforces minimum 1 OA per org
- All role changes logged in audit trail (who, when, from/to)

**Disable (soft-lock):**
- Immediate effect: login blocked, API keys suspended (not deleted — reactivate on re-enable)
- Reversible: re-enable restores access and unsuspends API keys
- **Last OA protection:** Cannot disable the last Org Admin
- Visual indicator on user row: greyed out + "Disabled" badge

**Delete (two-step, irreversible):**
- Prerequisite: user must be disabled first (cannot delete an active user)
- Confirmation dialog requires typing the user's name to confirm
- 30-day grace period: soft-deleted, can be restored. After 30 days, hard purge runs automatically.
- **Attribution on delete:** Default behavior is `Name [removed]` tag preserved in audit trail, comments, scan history
  - Org-level setting: "User Deletion Policy" with two options:
    - "Retain name in audit trail" (default, recommended for compliance)
    - "Anonymize completely" → replaces with `[Removed User]` everywhere (for GDPR strict interpretation)
  - Internal user ID preserved in both modes so audit entries still link to same deleted entity
- **Reassignment:** Findings assigned to deleted user become unassigned; admin prompted to reassign during deletion flow

**Auth-source awareness (Phase 6 prep):**
- UI conditionally renders actions based on `user.auth_source`:
  - `local`: full actions — Disable, Delete, Reset Password, Change Role
  - `scim/saml/oidc`: Change Role (with sync override warning), Disable (with "managed by IdP" warning), no Delete, no Reset Password, "Managed by [IdP name]" badge
- Phase 4.5 only wires `local` paths; SCIM/SAML conditional rendering present but code paths disabled until Phase 6

**Break-glass admin recovery:**
- **Self-hosted:** CLI command `cradar admin reset-password --email admin@org.com` — requires server shell access
- **SaaS/cloud:** Recovery key generated at org creation — one-time use, shown once, must be acknowledged ("I have saved this key" checkbox required to proceed). Stored hashed. Resets OA password when used via `/recover` endpoint, then invalidates (new key generated).
- **Both deployments:** Secondary recovery email (shared/team mailbox) required at org setup — separate from admin's personal email, can receive password reset if individual email is unreachable
- Recovery key format: `CRADAR-RCVR-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`

---

### D10: User Creation & Role Restriction (#20, #21, #23)

**Status:** LOCKED

**Dual creation flow (#20):**
- Single modal with toggle: "Send invite" (email-based) vs "Add directly" (set temp password)
- Invite: user receives email, sets own password via link
- Direct add: admin sets email + name + temporary password + role. Force-change on first login is non-negotiable.
- If SMTP not configured, invite tab shows "Email not configured — use direct add" message
- Both flows assign group at creation time

**Role dropdown restriction (#23):**
- Dropdown capped by the creator's own role level. Prevents privilege escalation.

| Creator Role | Can Assign |
|---|---|
| Org Admin | All 7 roles (OA, SM, SE, TM, CA, DEV, Guest) |
| Security Manager | SE, TM, CA, DEV, Guest |
| All others | Cannot create users |

- SM cannot create another SM or OA — only OA can create admin-tier roles
- Rationale: SM runs the security team and needs to onboard engineers without bottlenecking on OA, but should not be able to escalate privileges

**Bulk import (#21): DEFER with CLI bridge**
- No UI-based CSV import in Phase 4.5 — SCIM in Phase 6 is the proper enterprise answer
- CLI alternative for self-hosted: `cradar admin import-users --csv users.csv`
  - CSV format: email, name, role, group
  - Validates role caps (running user's role), rejects duplicates, reports errors
  - All imported users force-change password on first login
- Documented in CLI help and admin guide

**RBAC updates:**
- `Invite user`: OA + SM (was OA only)
- `Add user directly`: OA + SM (was OA only)
- SM creation scoped to SE and below

---

### D11: User Table UX — Pagination & Activity (#22, #24)

**Status:** LOCKED

**Pagination (#22):**
- Server-side offset pagination for user management table
- Default page size: 25, options: 10/25/50/100
- Standard controls: page numbers, prev/next, "Showing X–Y of Z"
- Search/filter applied before pagination (search by name/email/role)
- **Standard pagination pattern** for all Phase 4.5 tables: same component, same API contract (`page`, `per_page`, `total`, `items[]`)
- Reserve cursor pagination for high-volume endpoints (findings, audit log) if offset proves too slow

**User activity (#24):**
- Add "Last Active" column to user table (timestamp of most recent login or API activity)
- Stale indicators: orange dot if inactive > 30 days, red if > 90 days
- Low-effort: single DB field update on login
- Full session management deferred to Phase 6

**User detail drawer:**
- Click user row → side drawer with: profile, role, auth source, last active, group memberships with project list, API key count, quick actions
- Read-only group/project access view in Phase 4.5
- Group editing from Group Management page only (not from drawer)
- Phase 6: drawer may gain group edit capability if SCIM doesn't cover the need

---

### D12: Role Resolution Model — Per-Group Roles with Global Fallback (#22, #24, future AD)

**Status:** LOCKED

**Core model:**
- **Group role:** Primary role assignment. Comes from AD security group mapping (Phase 6) or manual assignment. Grants access to a specific group with a specific role.
- **Global role:** Supplementary floor. Gives access to ALL groups at that role's permission level. Admin-assigned in User Management.
- **Resolution:** `effective_role(user, group) = max(group_role, global_role)` — higher-privilege role always wins.

**Access rules:**
| Scenario | Access |
|---|---|
| Has group role for this group | Yes, at group role level |
| No group role, has global role | Yes, at global role level |
| Neither | No access |
| Has both | Yes, at max(group_role, global_role) |

**Cross-group views (portfolio, dashboard, global search):**
- User sees data from all groups they can access (via group role OR global role)
- Actions are per-item: governed by effective role in that item's group context
- e.g., can suppress a finding in Group B (where effective role = SE) but not in Group A (where effective role = Developer)

**Example:**
```
User A:
  AD group: PAYMENTS_BACKEND_DEV → Group "Payment Services", group_role: Developer
  Global role: Guest/Viewer

  → "Payment Services":    max(Developer, Guest) = Developer ✓
  → "Identity Platform":   max(none, Guest) = Guest/Viewer ✓ (readonly via global)
  → "Core Infra":          max(none, Guest) = Guest/Viewer ✓ (readonly via global)
  → Portfolio dashboard:   sees all 3 groups; actions scoped per-item
```

**Data model:**
- `user` table: `role` column (semantic: global_role, the floor)
- `user_group` junction: add `role` column (nullable, the group-specific role)
- Phase 4.5: `user_group.role` is nullable, everything uses global role (backward compatible)
- Phase 6: SCIM sync populates `user_group.role` from AD group mappings

**Phase 4.5 implementation:**
- Add nullable `role` column to `user_group` junction table (schema ready, not wired in UI)
- Permission-checking code uses `getEffectiveRole(user, group)` function that returns `max(user_group.role, user.role)` — today always returns `user.role` since `user_group.role` is null
- No per-group role UI in Phase 4.5; activated in Phase 6

---

### D13: Finding Table UX — Sorting, Pagination, Detection Column (#25, #26, #33)

**Status:** LOCKED

**Sorting (#25):**
- Sortable columns: Severity, File path, Algorithm/asset, First seen, Status, Confidence, Detection method
- Default sort: Severity descending (Critical → Info), then first-seen descending within each tier
- Single-column sort in Phase 4.5; multi-column (shift-click) deferred
- Click column header to toggle asc/desc, visual indicator on active sort column

**Pagination (#26):**
- Server-side offset pagination (same D11 pattern): `page`, `per_page`, `total`, `items[]`
- Default page size: 25, options: 10/25/50/100
- **File-grouped view toggle:** Alternative to flat list — group findings by file path with expandable rows:
  ```
  ▸ src/crypto/aes.go (4 findings)
  ▸ src/tls/config.go (7 findings)
  ```
  Toggle: "List view" / "File view" — both respect active filters and sort

**Detection column (#33):**
- Rename "Pass" column → "Detection"
- Values: "Pattern" (was Pass 1, tree-sitter) / "Taint" (was Pass 2, OpenGrep)
- Tooltip on column header: "How this finding was detected — Pattern: syntax matching, Taint: data flow analysis"

---

### D14: Finding Status Model & Lifecycle (#28, #31, #32)

**Status:** LOCKED

**Status set (6 statuses):**

| Status | Meaning | Who can set | Open? |
|---|---|---|---|
| **Open** | New finding, not yet triaged | System (auto) | Yes |
| **In Review** | Being investigated / assigned | SE, SM, OA | Yes |
| **In Progress** | Fix underway | SE, SM, OA, DEV | Yes |
| **Resolved** | Fix confirmed by next scan | System (auto) or SE/SM/OA | No |
| **Risk Accepted** | Org accepts the risk | SM, OA only | No |
| **False Positive** | Detection was wrong | SE, SM, OA | No |

**Auto-transitions (scan-driven):**

| Trigger | Transition |
|---|---|
| New scan detects finding for first time | → Open |
| Scan no longer detects a previously open finding | → Resolved (resolved_by: scan) |
| Scan re-detects a previously resolved finding | → Open (reopen_count++, last_reopened_at updated) |
| Scan detects a Risk Accepted / FP finding | No change — stays in current status |

- Reopened is NOT a separate status — Open with `reopen_count` metadata + "Reopened" badge in UI

**Mandatory justification on critical transitions:**

- **Risk Accepted** requires structured justification:
  - Reason dropdown: Compensating control / Low impact / Migration planned / Business exception
  - Detail: required freetext
  - Review date: required (when to re-evaluate — overdue warning surfaced when date passes)
  - Approved by: auto-filled from current user
- **False Positive** requires freetext justification explaining why detection is wrong
- **Risk Accepted reversal** (back to Open) requires freetext explaining why acceptance is revoked

**Risk Accepted — global enable/disable (org-level setting):**
- Admin > Org Settings:
  - Enabled: findings can be marked as Risk Accepted in CipherRadar
  - Disabled: Risk Accepted status hidden from all dropdowns and bulk actions; existing RA findings grandfathered
  - External portal URL (optional): shown as "Manage risk acceptance in [GRC Portal]" link where RA option would normally appear
- For orgs using central GRC platforms (ServiceNow, Archer, OneTrust)

**Findings display — status filter bar:**
```
[All] [Open (147)] [In Review (23)] [In Progress (31)] [Resolved (412)] [Risk Accepted (18)] [FP (9)]
```
- Default selection: Open + In Review + In Progress (the "active" set)
- Click to include/exclude any status
- Counts update in real-time with active filters

**Audit trail (#32):**
- `finding_status_history` table: finding_id, from_status, to_status, changed_by, changed_at, reason (nullable)
- **UI:** Compact "Recent Activity" summary (last 5 transitions) on FindingDetail page
- **Comments section (#31):** Always visible on FindingDetail, separate from status transitions
- **API:** `GET /api/v1/findings/{id}/history` — full transition history, JSON
- **Compliance report export:** Full audit chain per finding
- **Admin Audit Log:** Finding status changes also appear there (filtered by action type)

**MTTR calculation:**
- Per finding: resolved_at − first_seen (or opened_at for reopened findings)
- Aggregations: by severity, by group/project, monthly trend
- Only Open → Resolved transitions count — Risk Accepted and FP excluded from MTTR

---

### D15: FP/Risk Acceptance Request Workflow (NEW)

**Status:** LOCKED

**Problem:** Developers cannot directly set FP or Risk Accepted status (per RBAC). They need a way to request these dispositions with justification.

**Request flow:**
- Developer clicks "Request FP Review" or "Request Risk Acceptance" on a finding
- Must provide mandatory justification (same structured format as D14)
- Creates a pending request visible to SE/SM in a dedicated queue
- SE/SM approves (status changes) or rejects (request closed, finding stays open, rejection reason required)

**Approval queue (visible to SE, SM, OA):**
- Accessible from sidebar: "Pending Requests (N)" with count badge
- Table: finding summary, requester, request type (FP/RA), justification, requested date
- Actions per request: Approve, Reject (with reason), View Finding
- Sortable by: date, requester, severity, request type

**Soft rate limiting (anti-spam):**
- If user has > 10 pending requests (configurable at org level), show warning: "You have N pending requests awaiting review. Please wait for existing requests to be processed."
- Warning is advisory, not blocking — user can still submit
- SM/SE dashboard: "Top requesters" widget showing request counts and rejection rates
  - e.g., "Alex: 47 requests this month (38 rejected)" — conversation trigger, not system enforcement
- No hard block mechanism in Phase 4.5 — revisit if needed

**RBAC for requests:**

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| Raise FP/RA request | | | x | x | | x | |
| Approve/reject FP request | x | x | x† | | | | |
| Approve/reject RA request | x | x | | | | | |
| View request queue | x | x | x | x‡ | | | |

†SE can approve DEV/TM FP requests; SE's own FP requests require SM/OA approval
‡TM sees request queue for their own group only

Note: Only SM/OA can mark FP/RA directly. SE, TM, and DEV must use the request workflow. This ensures separation of duties — group-level personnel cannot unilaterally dismiss findings.

---

### D16: Rule Effectiveness Analytics (NEW)

**Status:** LOCKED

**Metrics per rule:**

| Metric | Calculation |
|---|---|
| Total findings | Count of all findings from this rule |
| Active findings | Count where status = Open/In Review/In Progress |
| FP rate | (FP findings / total findings) × 100 |
| Risk Accepted rate | (RA findings / total findings) × 100 |
| Fix rate | (Resolved / total findings) × 100 |
| MTTR | Avg time Open → Resolved for this rule's findings |
| Trend | Findings per scan over last N scans |

**Time window:** Default 90 days, dropdown options: 30d / 90d / 180d / 1y / All time

**Location: Enhanced Policy Rules page (Admin > Policy Rules)**
- Existing rule table gains new columns: Findings count, FP Rate, Fix Rate, MTTR
- Expandable row on click: trend chart, per-project breakdown, signal-vs-noise quadrant position
- Progressive disclosure: table for quick decisions, expanded detail for deep analysis

**Signal vs noise quadrant (in expanded detail):**
- Top-left (Valuable): Low FP, high fix rate — rule working well
- Top-right (Noisy but actioned): High FP, high fix rate — rule needs tuning
- Bottom-left (Ignored): Low FP, low fix rate — severity may need adjustment
- Bottom-right (Pure noise): High FP, low fix rate — candidate for disable/rewrite

**Automated warnings:**
- Per-rule warning icon: shown when FP rate > 50% or fix rate < 10% in current time window
- Tooltip: "This rule has a 67% false positive rate across 340 findings in the last 90 days"
- Rules page banner: "N rules have high FP rates — review recommended" (when any rule exceeds threshold)

**RBAC:** Same as Policy Rules page — OA, SM, SE can view. OA, SM can enable/disable rules.

---

### D17: SE & TM Role Refinement (#27, #29 + RBAC overhaul)

**Status:** LOCKED

**SE role changes (group-level security operations):**
- **Removed:** Direct FP/RA marking. SE can no longer unilaterally dismiss findings.
- **Removed:** Org Settings page access. SE has no org-wide admin access.
- **Changed:** Policy Rules page → view-only (can see rules + D16 analytics, cannot enable/disable).
- **Added:** Raises FP requests (requires SM/OA approval). Approves DEV/TM FP requests within group.
- **Rationale:** SE is a validator, not a unilateral authority. Separation of duties — the person reviewing code shouldn't also dismiss findings without oversight from central security.

**TM role expansion (app team workload manager):**
- **Added:** Assign findings to users within group
- **Added:** Change finding status (Open/In Review/In Progress)
- **Added:** Create Jira issues from findings
- **Added:** Raise FP/RA requests (with justification)
- **Added:** Bulk actions (assign + status change only, not FP/RA)
- **Added:** View FP/RA request queue for own group (to track team requests)
- **Not added:** Direct FP/RA marking, FP request approval, cross-group assignment
- **Rationale:** TM is the bridge between security team and dev team. SM/SE identify problems, TM distributes work to developers. Without TM having assign/Jira powers, SE becomes a bottleneck.

**Assignment model (#29):**

| Assigner | Scope |
|---|---|
| OA, SM | Any project, any group |
| SE, TM | Projects within their group(s) only |
| DEV | Self-assign unassigned findings in own group only |

- Single assignee per finding (no multiple assignees — clear ownership)
- Assignment auto-transitions finding to "In Review" if currently Open
- Assignee gets notification per their preferences
- "My Assigned Findings" section on developer dashboard
- DEV cannot steal findings assigned to someone else

**Separation of duties summary:**

| Tier | Roles | FP Power | RA Power |
|---|---|---|---|
| App team (requesters) | DEV, TM | Raise FP request | Raise RA request |
| Group security (validators) | SE | Approve DEV/TM FP requests; raise own FP requests | Raise RA request |
| Central security (authority) | SM, OA | Mark FP directly + approve any request | Mark RA directly + approve any request |

---

### D18: Jira Integration — Per-Group/Project Config (#30)

**Status:** LOCKED

**Two-tier Jira configuration:**

**Tier 1 — Org-level (D3, already decided):**
- Jira server URL + PAT token (connection credentials)
- Configured in Admin > Integrations
- OA/SM only

**Tier 2 — Group-level (NEW):**
- Per CipherRadar group: Jira project mapping
- Fields:
  - Jira project key (e.g., `PAYMENTS`)
  - Default issue type (Bug / Task / Story)
  - Priority mapping: CipherRadar severity → Jira priority
  - Custom fields mapping (optional, e.g., "Security Finding ID")
  - Default assignee (optional)
  - Labels/components to auto-add
- Configurable by: OA, SM, SE, TM

**Project-level override (optional):**
- Per CipherRadar project: override group Jira config if needed
- Same fields as group-level
- Inheritance: project config → group config → no config (button disabled)

**Config location:**
- Group-level: Group Settings > Jira Integration
- Project-level: Project Settings > Jira Integration (override section)

**"Create Jira Issue" behavior:**
- Uses project Jira config if set, else group config, else disabled with message "Configure Jira in group settings"
- Pre-fills: summary from finding title, description from finding detail + code snippet, priority from severity mapping
- User can edit before submitting
- Created Jira issue URL stored on finding record, shown as link in findings table
- Bidirectional: Jira issue status changes can optionally sync back (webhook from Jira → CipherRadar)

---

### D19: Bulk Actions (#27)

**Status:** LOCKED

**UX pattern:**
- Checkbox per row + "Select all on page" + "Select all matching current filter"
- Action bar appears when 1+ selected: `[N selected] [Assign ▾] [Status ▾] [More ▾] [Clear]`
- Available bulk actions governed by user's role (per D17 RBAC)

**Bulk actions by role:**

| Bulk Action | OA | SM | SE | TM | DEV |
|---|---|---|---|---|---|
| Assign to user | x | x | x | x | |
| Change status (Open/In Review/In Progress) | x | x | x | x | |
| Mark as FP (direct) | x | x | | | |
| Mark as RA (direct) | x | x | | | |
| Raise bulk FP request | | | x | x | x |
| Create single Jira issue (for batch) | x | x | x | x | |
| Export selected (CSV/JSON) | x | x | x | x | x |

- Bulk FP/RA still requires justification — one justification applies to all selected
  - e.g., "All findings in /test/ directory — test code, not production"
- Bulk Jira creates one ticket with all selected findings listed in description

---

### D20: Scan Management UX (#36–#40)

**Status:** LOCKED

**#36 — Scan progress feedback:** ACCEPT
- WebSocket-driven progress states: Queued → Cloning → Scanning (Pass 1/2) → Generating CBOM → Complete/Failed
- Progress shown on project page + toast on completion
- Backend Taskiq workers emit progress events

**#37 — Stale scan warning:** ACCEPT
- Conditional banner on project page when `last_scan_at > threshold`
- Org-configurable threshold, default 30 days

**#38 — Scan queue/status view:** ACCEPT
- Global "Scans" page in sidebar
- Table: project, trigger type (manual/scheduled/webhook/push), status, started, duration, triggered by
- Visibility scoped per D12 — users see scans for groups they can access
- Filters by status, project, trigger type

**#39 — Scan scheduling:** ACCEPT with three-tier inheritance
- Org default → Group override → Project override (same pattern as D18 Jira config)
- Simple presets: daily/weekly, pick time + timezone
- Stored as cron expression internally (full cron = future UI-only upgrade)
- Admin toggle: "Allow project-level schedule overrides" (org setting, default: on)
  - When off, projects inherit group/org schedule, per-project config hidden
- Resolution: project → group → org → none

**#40 — Scan rerun:** ACCEPT
- "Rerun" button clones scan config into a new scan with same parameters

---

### D21: Scan Provenance & Environment Tagging (NEW)

**Status:** LOCKED

**Provenance captured on every scan:**

| Scan type | Fields |
|---|---|
| Source (git) | branch, commit SHA, tag (if any) |
| Container | image ref, image digest (sha256) |
| Artifact | filename, checksum (sha256), version |

**Environment model:**
- Org-configurable promotion stages, default: `development → staging → production`
- Admin can add/reorder custom stages (uat, pre-prod, dr-site, etc.)
- Each scan tagged with at most one environment

**Promotion flow:**
- Tag moves with the artifact — same commit SHA / image digest = same CBOM, no re-scan needed
- If re-scan needed, retrigger manually or via CI script
- Two promotion paths:
  - **Manual:** scan history → "Promote to..." dropdown
  - **API:** `POST /api/v1/scans/promote` with `{commit_sha, from_env, to_env}` — called from CI/CD pipeline
- Old prod tag auto-demoted when new scan promoted (one active scan per environment per project)
- All promotions logged in audit trail

**What this unlocks:**
- Portfolio dashboard: "Production" filter → live crypto posture across all deployed services
- Compliance reports scoped by environment
- Drift detection: diff staging scan vs current prod scan before promotion
- MTTR scoped to production findings

**RBAC:**

| Action | OA | SM | SE | TM | DEV | CA | G |
|---|---|---|---|---|---|---|---|
| Promote (manual) | x | x | x | | | | |
| Promote (API) | scoped by API key | | | | | | |
| View environment tags | x | x | x | x | x | x | x |

---

### D22: Navigation & Information Architecture (#41–#47)

**Status:** LOCKED

**#41 — Project tab consolidation:** ACCEPT
- Reduce from 10+ tabs to 6:

| Tab | Contains |
|---|---|
| **Overview** | Summary, scan status, key metrics |
| **Findings** | Findings table (D13/D14), remediation |
| **Compliance** | Framework compliance + quantum readiness (merged) |
| **Dependencies** | Dependency graph + SBOM (merged) |
| **Scans** | Scan history, environment tags (D21), rerun |
| **Settings** | General, scan sources (D1), Jira config (D18), notifications, schedule (D20) |

- Quantum readiness becomes a section within Compliance tab (it's a compliance concern, not a separate domain)
- SBOM folds into Dependencies (related views)
- Settings absorbs all per-project config

**#42 — Breadcrumbs:** ACCEPT
- Format: `Acme Corp / Payment Services / payment-api / Findings`
- Clickable at each level, shown in top bar
- Breadcrumb reflects: Org → Group → Project → Tab/Page

**#43 — Global search (Ctrl+K):** ACCEPT (scoped for Phase 4.5)
- Command palette with Ctrl+K shortcut
- Phase 4.5 scope: project search + finding search (by algorithm, file path, rule ID)
- Full command palette with actions (trigger scan, change status, navigate) deferred

**#44 — Back navigation:** ACCEPT
- Browser history works naturally with TanStack Router
- Breadcrumbs solve most of the disorientation — no custom back button needed

**#45 — Two "Compliance" pages:** ACCEPT (resolved by #41)
- Project level: "Compliance" tab (merged with quantum per #41)
- Portfolio level: rename sidebar entry to "Portfolio Compliance"
- Clear distinction: project-scoped vs org-wide

**#46 — Sidebar icons:** ACCEPT
- Replace Unicode icons with Lucide React icon set (consistent, SVG-based, MIT licensed)

**#47 — Notification bell:** ACCEPT
- Bell icon in top bar with unread count badge
- Click opens notification dropdown (recent 5) with "View all" link to full notification page
- Supplements existing sidebar notification nav item

---

### D23: Empty/Placeholder Pages (#48–#50)

**Status:** LOCKED

**#48 — CertCalendar:** ACCEPT — rename to "Certificate Tracker"
- Portfolio-level view (cross-project), not per-repo
- Timeline/calendar showing certificate expiry dates across all projects
- Color-coded: green (>90d), amber (30–90d), red (<30d), black (expired)
- Data sourced from CBOM certificate findings (already detected by scanner)
- Integrates with notification system for expiry alerts (configurable thresholds)
- Lives under Portfolio nav section

**#49 — MigrationKanban:** REJECT Kanban concept → ACCEPT as "PQC Migration Progress" section
- Kanban is wrong metaphor — nobody drags cards, Jira handles task management (D18)
- CipherRadar's unique value: aggregate migration posture that Jira can't answer
- Becomes a read-only dashboard section within Portfolio Compliance (D22 merged quantum into compliance)
- Shows:
  - % of crypto that is quantum-vulnerable (org-wide)
  - Migration progress by algorithm family (RSA → ML-KEM, ECDSA → ML-DSA, etc.) with project counts per stage
  - Lagging projects
  - On-track indicator against org quantum deadline
- Derived entirely from scan data + quantum algorithm table + D14 finding statuses
- No separate page — no manual tracking, no workflow, no Jira overlap

**#50 — Router catch-all:** ACCEPT
- Proper 404 page with helpful message + link back to project overview

---

### D24: Onboarding & Empty States (#51–#55)

**Status:** LOCKED

**#51 — First login onboarding:** ACCEPT
- Three-step wizard on first OA/SM login only: Connect git provider (D3) → Import projects → Trigger first scan
- Not a full product tour — just the critical path to value
- Other roles (joining an existing org): skip wizard, see contextual "Getting Started" card on dashboard

**#52–#54 — Empty states:** ACCEPT (batch)
- Standard pattern: illustration + one-line explanation + primary action button
- Per-context copy:
  - No projects: "Connect a Git Provider" → links to D3 flow
  - No findings match: "No findings match your filters" + "Clear Filters" button
  - No scans: "Run Your First Scan" → links to scan modal (D1)
- Single reusable `EmptyState` component with per-context props

**#55 — Guest role explanation:** ACCEPT
- Persistent info banner on first Guest login: "You have view-only access. Contact your admin for elevated permissions."
- Dismissable, shown once (preference stored in localStorage)

---

### D25: Toast Notifications (#56, #58, #61)

**Status:** LOCKED

- Global toast system: success (auto-dismiss) and error (persistent with retry) on every mutation
- One `useToast` hook + one `<Toaster />` component, app-level — not per-page
- #58 (Plan field): remove entirely. Dead UI with no backend. If SaaS billing needed later, it gets its own page.

---

### D26: Cascading Config / Policy Inheritance (#57)

**Status:** LOCKED

**Model:** Rules detect. Policies control the response — and cascade org → group → project.

```
Rule: "detect MD5 usage"             ← same everywhere
Policy: "MD5 = CRITICAL, block CI"   ← varies per level
```

**Policy settings that cascade:**
- Rule severity overrides (org says HIGH, project says CRITICAL)
- CI fail thresholds (fail on HIGH+ vs MEDIUM+)
- Rule enable/disable per scope
- Applies same inheritance pattern as D18 (Jira) and D20 (scheduling)

**Lock mechanism:** OA can lock specific policy settings to prevent group/project overrides (e.g., "FIPS rules cannot be disabled").

**RBAC:**

| Action | OA | SM | SE and below |
|---|---|---|---|
| Set org policy | x | | |
| Override at group | x | x | |
| Override at project | x | x | |
| Lock (prevent override) | x | | |
| View policy | x | x | x |

---

### D27: Custom Rules & Rule Management (#59, #60)

**Status:** LOCKED

**Custom rule lifecycle:**
1. Admin uploads rule in portal → validated against OpenGrep schema + dry-run tested
2. Stored in DB + written to `scanner/rules/custom/` in source repo
3. Immediately active for portal scans (worker loads from DB)
4. CLI auto-syncs at scan start:
   - Checks portal for rules not in local cache (`~/.cradar/rules/`)
   - Downloads delta silently
   - If sync fails: warning message, continues with available rules
   - Portal URL + auth from `.cradar.yml` (ADR-025) — no extra config
   - No portal configured: skips sync, uses embedded rules only
5. Next release: review custom rules — promote to built-in (`scanner/rules/<lang>/`) or keep as custom

**Rule forking:** Admin can clone a built-in rule and modify it. Fork tagged `custom-`, linked to parent. Parent updates trigger notification to review fork.

**Rule search (#60):** Filter bar on rules table — by language, source (built-in/custom), severity, enabled/disabled.

**Severity overrides:** Covered by D26 policy cascade, not custom rules.

---

### D28: Audit Log (#62–#66)

**Status:** LOCKED

**Events logged** (from prior decisions): user lifecycle (D9/D10), finding status changes (D14), FP/RA requests (D15), assignments (D17), Jira issues (D18), environment promotions (D21), API key ops (D7).

**Filters (#62, #63):**

| Filter | Options |
|---|---|
| Date range | Presets: today, 7d, 30d, 90d, custom range |
| Actor | User dropdown |
| Action type | Login, scan, finding change, user mgmt, policy change, API key, promotion |
| Project/Group | Scope to specific project or group |

**Pagination (#65):** Server-side, same D11 pattern (25/50/100 per page).

**CSV export (#64):** Download with active filters applied.

**Webhook export:** Configure URL in admin → audit events pushed as JSON in real-time. Covers Splunk/Sentinel/QRadar.

**Retention:** Org setting, default 2 years. Archived after (still queryable, slower).

**RBAC (#66):**

| Role | Access |
|---|---|
| OA | Full — all events, all groups |
| SM | Full — all events, all groups |
| CA | Full — read-only, all groups |
| SE | Scoped to their group's events |
| TM, DEV, Guest | No access |

---

### D29: Visual & Theme (#67–#75)

**Status:** LOCKED

**#67–#68 — Hardcoded colors:** ACCEPT
- Move all component colors (dependency graph, compliance framework) to CSS theme variables
- One fix, both items resolved

**#69 — Crystal theme contrast:** ACCEPT
- Adjust `--text-4` / `--bg-0` values to pass WCAG AA (4.5:1 ratio)

**#70–#72 — Responsive design:** ACCEPT for tablet/small laptop (≥1024px), DEFER true mobile (<768px)
- Enterprise security tool — users are on laptops, not phones
- Sidebar collapses at 1024px breakpoint, tables get horizontal scroll, grid reflows to single column

**#73–#74 — Badge/font consistency:** ACCEPT
- Standardize badges to CSS classes (no inline styles)
- Define type scale: 5 sizes (12/14/16/20/24px) + semantic names (body, label, heading, title, display)

**#75 — Theme preview:** ACCEPT
- Replace colored dots with small thumbnail previews showing actual theme appearance

---

### D30: Login & Auth (#76–#81)

**Status:** LOCKED

**#76 — Forgot Password:** ACCEPT
- Email with reset link if SMTP configured, otherwise "contact your admin"
- Admin force-reset already covered by D6

**#77 — Sign-up flow:** REJECT
- Enterprise tool — orgs are provisioned, not self-signed-up
- First org created during deployment setup (CLI or first-run wizard)

**#78 — Login error message:** REJECT (intentional)
- Keep vague: "Invalid credentials" — distinguishing email vs password leaks account existence

**#79 — Member Since date:** ACCEPT
- Pull from `users.created_at`. One-liner.

**#80 — Change Email:** ACCEPT (admin-only)
- User requests, OA approves. Prevents account hijacking.
- Self-service with email verification deferred to Phase 6

**#81 — Session management:** DEFER to Phase 6
- Needs JWT refresh token infra, device tracking, token revocation
- Ties into SSO/MFA work

---

### D31: Notifications & Integrations (#82–#86)

**Status:** LOCKED

**#82 — Slack integration:** DEFER. Not in scope.

**#83 — Webhook test button:** ACCEPT
- "Send test" button next to any configured webhook URL. Shows success/fail inline.

**#84 — Quiet hours/DND:** DEFER. Users manage this in their own tools.

**#85 — Synced repos indicator:** ACCEPT
- Per provider: "GitHub: 8 repos synced, 3 available" with last sync timestamp
- Data already available from D3 repo picker

**#86 — Token rotation/revoke:** ACCEPT
- Revoke + re-enter new token flow
- Show token age, "rotate recommended" warning after 90 days

---

### D32: Accessibility (#87–#93)

**Status:** LOCKED

**#87 — Keyboard navigation:** ACCEPT
- Tab through tables, sidebar, filters. Standard HTML semantics + `tabindex` where needed.

**#88 — Keyboard shortcuts:** Already covered by D8 (#11)
- Modal reference exists, actual shortcut implementation deferred

**#89, #91 — Screen reader basics:** ACCEPT
- `scope="col"` on table headers, `aria-label` on icon-only buttons
- Mechanical fixes, applied during component work

**#90 — Graph accessibility:** ACCEPT (limited)
- Canvas graphs can't be fully screen-reader accessible
- Add `aria-label` with summary ("Dependency graph: 47 nodes, 3 critical")
- Table-based alternative view toggle for full data access
- **Legend fix:** replace text descriptions with actual mini SVG shapes + colors matching graph nodes (square = library, circle = algorithm, diamond = certificate, etc.)

**#92 — Focus states:** ACCEPT
- CSS `:focus-visible` on all interactive elements

**#93 — Focus trap in modals:** ACCEPT
- Use `@radix-ui/react-focus-guard` (already in shadcn/ui stack)

---

## All 93 Items Reviewed

| Decision | Status | Count |
|---|---|---|
| ACCEPT | Will fix in Phase 4.5 | 74 |
| REJECT | Won't fix (by design) | 4 |
| DEFER | Later phase | 8 |
| DISABLE | Remove from UI | 2 |
| Covered by other D# | Already addressed | 5 |
