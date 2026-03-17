# ADR-006: RBAC Design — Roles, Permissions, API Key Model

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-16 |
| **Deciders** | Design session |
| **Supersedes** | — |
| **Superseded by** | — |

---

## Context

CipherRadar serves multiple distinct user personas (CISO, Security Engineer, Compliance Auditor, Developer, external auditors) across multi-tenant deployments. Each persona needs a different scope of access. Without a formal RBAC model, either all users have too much access (security risk) or access control is ad-hoc and inconsistent (maintenance burden).

The product also needs API key support for CI/CD pipelines, and a suppression workflow that preserves audit integrity.

## Decision

Implement a role-based access control system with:
- Six human roles: Org Admin, Security Manager, Security Engineer, Compliance Auditor, Developer, Guest/Viewer
- One non-human role: CI/CD Service Account (API key-based)
- Nested group hierarchy (Org → Groups → Projects) with role assignment at any level cascading downward
- Suppression request workflow: Developer raises request → Security Engineer approves/rejects
- Policy editing restricted to UI only — no API key scope for policy writes
- API keys configurable at creation: scopes + validity period + access range

## Rationale

- Role granularity maps to real personas and their actual information needs — avoids both over-privileged and under-privileged access
- Nested groups (not flat teams) accommodate enterprise org structures (Department → Squad) without forcing a fixed hierarchy depth
- Suppression workflow prevents Developers from silently hiding findings while still letting them flag false positives
- UI-only policy editing prevents automated or accidental policy changes via CI/CD scripts
- Configurable API keys (scopes + validity + range) give Security Engineers fine-grained control over CI/CD access without creating org-wide keys

## Consequences

- **Positive:** Clear accountability — every action is tied to a role; audit evidence is role-attributed
- **Positive:** Developers can participate in security workflow (raise requests) without bypassing it
- **Positive:** Flexible group hierarchy accommodates startups to large enterprises
- **Negative:** More roles than a simple admin/user model — requires UX investment to make role assignment intuitive
- **Negative:** Suppression approval workflow adds latency for Developer false positive fixes

## Alternatives Considered and Rejected

| Option | Reason Rejected |
|---|---|
| Simple admin / user two-role model | Too coarse — Compliance Auditor needs read-only access that admin would exceed; Developer needs project-scoped access that user might not |
| Flat team structure (no nesting) | Cannot represent Department → Squad hierarchy needed by enterprise orgs |
| Developer can suppress directly | Removes audit trail integrity; findings could be silently hidden without security review |
| API keys with policy:write scope | Enables automated policy changes via CI/CD — violates the principle of human-reviewed policy governance |

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/09-rbac.md` | New document created to detail the full RBAC design |
| `docs/02-architecture.md` | Multi-tenant isolation section updated; RBAC doc referenced |
