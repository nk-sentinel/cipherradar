# CipherRadar — RBAC Reference Matrix

> **Version:** v1 | **Date:** 2026-03-22
> **Source of truth:** `frontend/src/lib/roles.ts` + this document for action-level permissions

---

## Roles Overview

| Role | Abbr | Purpose |
|---|---|---|
| **Org Admin** | OA | Full platform control. User management, org settings, integrations, audit. |
| **Security Manager** | SM | Security policy, scan management, compliance oversight. Near-admin without user/billing management. |
| **Security Engineer** | SE | Group-level security operations: scanning, triage, FP request approval, finding analysis. Cannot directly mark FP/RA — validates DEV/TM requests. |
| **Team Manager** | TM | App team leadership: assign findings, track progress, create Jira issues, raise FP/RA requests. Workload manager for their group. |
| **Compliance Auditor** | CA | Compliance assessment, gap analysis, evidence collection. Read-only + export. |
| **Developer** | DEV | View own findings, get AI fixes, understand crypto posture. Limited scope. |
| **Guest / Viewer** | G | Read-only repo list. Onboarding or external stakeholders. |

---

## Page Access Matrix

| Page | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| **Overview** | | | | | | | |
| Dashboard | x | x | x | x | x | x | |
| Assets | x | x | x | x | x | x | |
| Repositories / Projects | x | x | x | x | x | x | x |
| **Portfolio** | | | | | | | |
| Quantum Readiness | x | x | x | x | x | | |
| Compliance | x | x | x | x | x | | |
| Compliance Dashboard | x | x | x | x | x | | |
| Dependency Graph | x | x | x | x | x | x | |
| Certificates | x | x | x | x | x | | |
| CBOM Diff | x | x | x | x | x | x | |
| Migration Kanban | x | x | x | x | x | x | |
| **Intelligence** | | | | | | | |
| Runtime Enrichment | x | x | x | x | | | |
| Agility Score | x | x | x | x | x | x | |
| HNDL Risk | x | x | x | x | x | | |
| CVE Correlation | x | x | x | x | x | x | |
| **Admin** | | | | | | | |
| Org Settings | x | x | | | | | |
| Policy Rules (edit) | x | x | | | | | |
| Policy Rules (view-only) | x | x | x | | | | |
| User Management | x | x | | | | | |
| Integrations | x | x | | | | | |
| Audit Log | x | x | | | | | |
| Artifact Registries | x | x | | | | | |
| AI Remediation Config | x | | | | | | |
| **User** | | | | | | | |
| Profile / Settings | x | x | x | x | x | x | x |
| Notification Preferences | x | x | x | x | x | x | |
| CLI Downloads | x | x | x | x | x | x | |
| Project Settings | x | x | x | x | x | x | |
| FP/RA Request Queue | x | x | x (approve) | x (view own group) | | | |

---

## Action Permissions Matrix

### Scanning

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| Trigger scan (own group projects) | x | x | x | | | | |
| Trigger scan (any project) | x | x | | | | | |
| View scan results | x | x | x | x | x | x | |
| View scan queue/status | x | x | x | | | | |
| Cancel running scan | x | x | | | | | |
| Configure scan schedule | x | x | | | | | |

### Findings

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| View findings | x | x | x | x | x | x | |
| Get AI remediation | x | x | x | | | x | |
| Mark as False Positive (direct) | x | x | | | | | |
| Mark as Risk Accepted (direct) | x | x | | | | | |
| Raise FP request (approval workflow) | | | x | x | | x | |
| Raise RA request (approval workflow) | | | x | x | | x | |
| Approve/reject FP request | x | x | x† | | | | |
| Approve/reject RA request | x | x | | | | | |
| View request queue | x | x | x | x‡ | | | |
| Change finding status (Open/In Review/In Progress) | x | x | x | x | | x** | |
| Assign finding to user (within group) | x | x | x | x | | | |
| Assign finding to user (any group) | x | x | | | | | |
| Self-assign unassigned findings (own group) | | | | | | x | |
| Create Jira issue from finding | x | x | x | x | | | |
| Add comment to finding | x | x | x | x | | x | |
| Bulk actions (assign/status) | x | x | x | x | | | |
| Bulk actions (FP/RA direct) | x | x | | | | | |

**Developer can only set In Progress on findings assigned to them
†SE can approve DEV/TM FP requests within their group; SE's own FP requests require SM/OA approval
‡TM sees request queue for their own group only (to track what their team has raised)

### Projects

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| View projects | x | x | x | x | x | x | x |
| View project settings | x | x | x | x | x | x | |
| Create project (git import) | x | x | | | | | |
| Create project (vendor/standalone) | x | x | | | | | |
| Edit project settings | x | x | | | | | |
| Link scan sources (container/artifact) | x | x | | | | | |
| Delete project | x | | | | | | |

### User Management

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| View all users | x | x | | | | | |
| Invite user | x | x* | | | | | |
| Add user directly (no invite) | x | x* | | | | | |
| Change user role | x | | | | | | |
| Disable user | x | | | | | | |
| Delete user | x | | | | | | |
| Reset user password | x | | | | | | |
| View all org API keys | x | x* | | | | | |
| Revoke any API key | x | | | | | | |

*Security Manager: read-only view of all keys; can invite/add users up to SE level only (cannot create OA or SM)

### API Keys (Self-Service)

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| Create own API key | x | x | x | x | x | x | |
| View own API keys | x | x | x | x | x | x | |
| Revoke own API keys | x | x | x | x | x | x | |

### Compliance & Reporting

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| View compliance dashboards | x | x | x | x | x | | |
| Export compliance report | x | x | x | | x | | |
| Export PQC report | x | x | x | | x | | |
| Export CBOM (JSON/SARIF/PDF) | x | x | x | x | x | x | |
| View audit log | x | x | | | | | |
| Export audit log (CSV) | x | x | | | | | |

### Configuration

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| Edit org settings | x | x | | | | | |
| Manage policy rules (enable/disable) | x | x | | | | | |
| View policy rules + analytics (read-only) | x | x | x | | | | |
| Manage integrations — org level (Git/Jira/Teams) | x | x | | | | | |
| Manage artifact registries | x | x | | | | | |
| Configure Jira project mapping (group level) | x | x | x | x | | | |
| Configure Jira project mapping (project override) | x | x | x | x | | | |
| Configure AI remediation | x | | | | | | |
| Configure notification preferences | x | x | x | x | x | x | |

### Profile

| Action | OA | SM | SE | TM | CA | DEV | G |
|---|---|---|---|---|---|---|---|
| Change own password (local auth) | x | x | x | x | x | x | x |
| Change theme | x | x | x | x | x | x | x |
| Enable MFA (Phase 6) | x | x | x | x | x | x | |
| View CLI downloads | x | x | x | x | x | x | |

---

## Scope Definitions (for API Keys)

| Scope | Description | Available To |
|---|---|---|
| `scan:read` | View scan results and status | All except Guest |
| `scan:write` | Trigger scans, upload results | OA, SM, SE |
| `cbom:read` | Download CBOM documents | All except Guest |
| `cbom:write` | Upload/modify CBOM documents | OA, SM, SE |
| `project:read` | View project metadata | All except Guest |
| `project:write` | Create/modify projects | OA, SM |
| `report:read` | Generate and download reports | OA, SM, SE, CA |
| `finding:write` | Suppress, assign, comment on findings | OA, SM, SE |

**Rule:** A user can only create API keys with scopes their role permits. A Developer cannot create a key with `scan:write` scope.

---

## Notes

1. **Role resolution (D12):** `effective_role(user, group) = max(group_role, global_role)`. Group role is primary (from AD/manual). Global role is the floor — gives access to ALL groups at that level. Higher-privilege role always wins. Cross-group views show all accessible data; actions are per-item by effective role in that item's group. See D12 for full details.
2. **Group-scoped access:** All "view" and "action" permissions are further scoped by group membership or global role. A user with no group role and no global role cannot see any group's projects.
3. **Auth source affects Profile:** When `auth_source` = saml/oidc/scim, password change and MFA are hidden (managed by IdP). See Phase 6.
4. **Audit log access:** Both Org Admin and Security Manager can view. Only Org Admin can export. (Bug fix: `PAGE_ACCESS` for security-manager already includes `admin-audit-log`.)
5. **Guest limitations:** Can only view repository/project list with basic metadata. Cannot enter any project, view findings, or access any other page.
6. **Last OA protection:** System prevents disabling, deleting, or demoting the last Org Admin. Minimum 1 OA enforced at all times.
7. **User deletion policy:** Org-level setting controls whether deleted user names are retained (`Name [removed]`) or fully anonymized (`[Removed User]`) in audit trails and comments. Default: retain name.
8. **Auth-source-aware actions:** Disable/Delete/Reset Password only available for `auth_source = local`. SCIM/SAML users show Change Role (with override warning) and Disable (with sync warning) only. See D6/D9.
9. **Break-glass recovery:** Self-hosted uses CLI `cradar admin reset-password`. SaaS uses recovery key generated at org creation. Both require secondary recovery email at org setup.
10. **User creation permissions (D10):** OA can create users with any role. SM can create users up to SE level. All others cannot create users.

---

## Change Log

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-22 | Initial RBAC reference from UX audit session |
| v2 | 2026-03-25 | Added D9–D12: user lifecycle, creation perms, role resolution model, per-group roles |
| v3 | 2026-03-25 | D17: SE loses direct FP/RA + org settings; TM gains assign/Jira/status/bulk; D18: per-group Jira config |
