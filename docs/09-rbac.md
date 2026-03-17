# Role-Based Access Control (RBAC)

> **Document version:** v1
> **Created:** 2026-03-16
> **Last updated:** 2026-03-17
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-16 | Initial document | ADR-006 |

---

## 1. Deployment Context

RBAC applies to the server-based deployments only. The CLI tool operates as a single-user tool authenticated via API key.

| Deployment | RBAC Applies? |
|---|---|
| CLI (local / CI/CD) | No — single user; authenticated via scoped API key |
| SaaS (multi-tenant) | Yes — full org/team/project hierarchy |
| Self-hosted (enterprise) | Yes — same model + optional LDAP/AD integration |

---

## 2. Tenant Hierarchy

```
Organization
 └── Groups  (nestable — unlimited depth)
      └── Groups  (sub-groups: departments, squads, business units, etc.)
           └── Projects (Repositories)
                └── Scans / CBOMs / Findings / Policies
```

The **Group** layer is intentionally flexible — it does not map to a fixed org-chart concept. An organisation decides what depth and naming makes sense for them:

| Organisation Type | Typical Group Structure |
|---|---|
| Startup / small team | One level: squads (Backend, Frontend, Mobile) |
| Mid-size product company | One level: product domains (Payments, Identity, Growth) |
| Large enterprise | Two levels: Department → Team (Engineering → Backend Squad) |
| Regulated enterprise | Two levels: Compliance Domain → Service Group (PCI Scope → Card Processing) |

**Example — large enterprise:**
```
Acme Corp  (Organisation)
 ├── Engineering  (Group — Department)
 │    ├── Backend Squad  (Group — Team)
 │    │    ├── auth-service
 │    │    └── user-api
 │    └── Platform  (Group — Team)
 │         └── infra-core
 └── Finance  (Group — Department)
      └── Payments  (Group — Team)
           └── payment-gateway
```

Roles are assigned at **org level**, **group level** (any depth), or **project level**. Permissions are additive — the most-permissive assignment wins. A role assigned at a parent group cascades down to all child groups and projects within it.

---

## 3. Roles

### 3.1 Human Roles

| Role | Persona | Summary |
|---|---|---|
| **Org Admin** | Platform / IT Admin | Full control — users, billing, org settings, all features |
| **Security Manager** | CISO / Security Leadership | Read all repos; configure org-wide policy; approve suppression requests; export audit evidence |
| **Security Engineer** | AppSec / Security Architect | Manage scanners and policies; view and suppress findings; approve/reject Developer suppression requests |
| **Compliance Auditor** | GRC / External Auditors | Read-only — compliance reports, signed CBOMs only, audit evidence; cannot suppress or modify anything |
| **Developer** | Developer / DevSecOps | View findings on own projects; trigger scans on own repos; raise suppression requests (requires approval) |
| **Guest / Viewer** | External auditors, stakeholders, contractors | Read-only access to a specific group or project's findings and signed CBOMs; no action permissions |

### 3.2 Non-Human Role

| Role | Usage |
|---|---|
| **CI/CD Service Account** | API key-based; scopes, validity, and access range defined at key creation time; no dashboard access |

---

## 4. Permission Matrix

| Resource / Action | Org Admin | Security Manager | Security Engineer | Compliance Auditor | Developer | Guest / Viewer |
|---|---|---|---|---|---|---|
| Org settings / billing | CRUD | R | — | — | — | — |
| User & team management | CRUD | R | — | — | — | — |
| Add / remove groups | CRUD | CRUD | — | — | — | — |
| Add / remove projects | CRUD | CRUD | CRUD | R | R (own) | — |
| Trigger scans | ✓ | ✓ | ✓ | — | ✓ (own) | — |
| View findings | ✓ | ✓ | ✓ | ✓ | ✓ (own) | ✓ (scoped) |
| Suppress findings (direct) | ✓ | ✓ | ✓ | — | — | — |
| Raise suppression request | ✓ | ✓ | ✓ | — | ✓ (own) | — |
| Approve / reject suppression request | ✓ | ✓ | ✓ | — | — | — |
| View CBOMs | ✓ | ✓ | ✓ | Signed only | ✓ (own) | Signed only |
| Export / download CBOMs | ✓ | ✓ | ✓ | Signed only | — | — |
| Create / edit policies | ✓ | ✓ | ✓ | R | — | — |
| Policy applies at | Org | Org | Org | — | — | — |
| View compliance reports | ✓ | ✓ | ✓ | ✓ | — | — |
| Export audit evidence package | ✓ | ✓ | ✓ | ✓ | — | — |
| Portfolio dashboard | ✓ | ✓ | ✓ | ✓ | — | — |
| Manage integrations (Jira/Slack) | ✓ | ✓ | ✓ | R | — | — |
| Create API keys | ✓ | ✓ | ✓ | — | — | — |

---

## 5. Role Assignment Scoping

Roles can be assigned at any level of the group hierarchy. Permissions cascade downward — a role assigned at a parent group applies to all child groups and projects within it.

| Assignment Level | Example |
|---|---|
| **Org-level** | Security Engineer sees all projects across the entire organisation |
| **Group-level (Department)** | Security Manager scoped to Engineering department sees only Engineering's repos |
| **Group-level (Team/Squad)** | Developer assigned to Backend Squad sees only that squad's repos |
| **Project-level** | Contractor given Guest/Viewer access to one specific repository |

The same user can hold **different roles at different levels** — e.g., a Developer at the org level who is also a Security Engineer for one specific project.

---

## 6. Suppression Request Workflow

Developers cannot suppress findings directly. The flow is:

```
Developer fills suppression request form
  → Comment validated before submission (see below)
  → On validation pass: request submitted
  → Security Engineer (or above) receives notification
      ├── Approve → must set expiry date (or explicitly select "No expiry")
      │             finding marked suppressed (approver + expiry + timestamp logged)
      └── Reject  → finding remains open; developer notified with reason
```

### 6.1 Suppression Request Fields (Developer)

| Field | Required | Notes |
|---|---|---|
| Finding ID(s) | Yes | Auto-populated from the finding |
| Reason category | Yes | `false-positive` / `risk-accepted` / `not-applicable` / `test-code` |
| Justification comment | **Mandatory** | Free-text; minimum 20 characters; validated before submission |

### 6.2 Comment Validation (Pre-Submission)

Before the request is submitted, the justification comment is validated to reject low-quality or unrelated input. The form blocks submission and shows an inline error if the comment:

- Is too short (< 20 characters)
- Is generic filler — e.g., `"fix later"`, `"not an issue"`, `"ok"`, `"test"`, `"NA"`, `"n/a"`, `"TODO"`
- Does not relate to the selected reason category (e.g., selecting `false-positive` but writing about a deployment timeline)
- Contains only punctuation or whitespace

Validation is performed client-side (fast feedback) with a server-side repeat check on submission. Rejected comments return a specific inline message — e.g., *"Your justification is too generic. Explain why this specific finding is a false positive in the context of this code."*

### 6.3 Approval Fields (Security Engineer)

| Field | Required | Notes |
|---|---|---|
| Decision | Yes | Approve / Reject |
| Expiry | **Mandatory on Approve** | Date picker — must explicitly choose a date **or** select "No expiry"; no default |
| Rejection reason | Yes (on Reject) | Free-text; sent back to Developer |

When a suppression expires, the finding automatically re-opens and the Developer receives a notification.

### 6.4 Audit Trail

Every suppression action (submission, approval, rejection, expiry, re-open) is immutably logged with: actor, timestamp, comment/reason, expiry date. Included in the audit evidence package.

---

## 7. Policy Scope

Policy rules are **org-level only**. There are no group or project-level policy overrides.

**Rationale:** Group or project-level overrides would allow individual teams to silently exempt themselves from compliance requirements, fragmenting the portfolio's crypto posture and invalidating audit evidence.

**UI-only editing:** Policies can only be created or modified through the dashboard UI. There is no API endpoint or API key scope for policy writes. This ensures all policy changes are deliberate, human-initiated actions with a visible audit trail — preventing automated or accidental policy modifications via CI/CD pipelines or scripts.

**Exception process:** If a project legitimately needs a policy exception (e.g., a legacy service awaiting migration), the exception is modelled as a time-limited suppression with Security Manager approval — not as a policy rule change.

---

## 8. Guest / Viewer Role

Guest/Viewer is designed for:
- External auditors performing a point-in-time review
- Third-party contractors scoped to a specific project
- Executive stakeholders who need to see reports without action permissions

**Constraints:**
- Must be explicitly assigned to a specific group or project (cannot be org-wide)
- Read-only on findings and signed CBOMs only (unsigned CBOMs not visible)
- Cannot export audit evidence packages (Compliance Auditor role required)
- Session-limited: Guest accounts can be given an expiry date at invitation time
- Cannot invite other users

---

## 9. API Key Management

### 9.1 Who Can Create Keys

API keys can be created by: **Org Admin, Security Manager, Security Engineer** only. Developers do not have API key creation rights — their CI/CD access is provisioned by a Security Engineer on their behalf.

### 9.2 Configurable at Creation Time

Every API key has three configurable dimensions set at the time of creation and cannot be changed after issuance (revoke and re-issue to change):

| Dimension | Options |
|---|---|
| **Scopes (permissions)** | Select any combination from the scope list below |
| **Validity period** | 7 days / 30 days / 90 days / 1 year / No expiry (requires explicit choice; no default) |
| **Access range** | Org-wide / Specific group(s) (any depth) / Specific project(s) |

### 9.3 Available Scopes

| Scope | Permission Granted |
|---|---|
| `scan:write` | Submit new scan jobs |
| `scan:read` | Read scan status and results |
| `cbom:read` | Read CBOM artifacts |
| `cbom:export` | Download / export CBOMs (signed only for Compliance Auditor-equivalent keys) |
| `findings:read` | Read findings list and detail |
| `findings:suppress:request` | Raise suppression requests (does not approve) |
| `policy:read` | Read policy rules and evaluation results |
| `reports:read` | Access compliance and summary reports |
| `reports:export` | Export reports (PDF, CSV, SARIF) |

### 9.4 Key Lifecycle

- Key value is shown **once** at creation — not stored in plaintext; hashed in DB
- Keys can be **revoked** at any time by the creator or an Org Admin
- All key usage is **audit-logged** (key ID, action, timestamp, source IP)
- Keys approaching expiry trigger a notification to the creator (7-day warning)
- Expired keys are automatically deactivated; not deleted (audit trail retained)

---

## 10. Authentication Methods


| Method | Deployment |
|---|---|
| Username + password | SaaS baseline |
| MFA | Optional for all users; Org Admin can enforce it org-wide |
| SSO via OIDC | SaaS + Self-hosted (Google Workspace, Okta, Auth0, Azure AD) |
| SSO via SAML 2.0 | Self-hosted enterprise |
| LDAP / Active Directory | Self-hosted enterprise only |
| API key | CI/CD, programmatic access |

**MFA details:**
- MFA is **optional at the user level** by default
- Org Admin can **enforce MFA org-wide** or for specific roles (e.g., require MFA for Security Manager and above)
- Supported MFA methods: TOTP (Google Authenticator, Authy, 1Password), WebAuthn / passkey (hardware security keys, biometrics)
- External MFA system integration: organisations with an existing MFA provider (Duo, Okta Verify, Microsoft Authenticator, RSA SecurID) can connect it via OIDC or RADIUS — CipherRadar defers the MFA challenge to the external system
- Guest/Viewer accounts: MFA optional; enforced only if the org-wide MFA policy requires it

---

## 11. Multi-Tenancy & Data Isolation

- Each organisation is a hard tenant boundary
- Database row-level security (PostgreSQL RLS) enforces tenant isolation at the data layer — not just the application layer
- Cross-tenant data access is architecturally impossible, not just policy-prevented
- SaaS shared infrastructure; self-hosted is single-tenant by definition

---

## 12. Open Items

| # | Question | Status |
|---|---|---|
| OQ-RBAC-5 | Should suppression request expiry be mandatory or optional? | **Resolved** — Approver must set expiry or explicitly select "No expiry"; Developer comment is mandatory and validated pre-submission |
| OQ-RBAC-6 | Should Guest/Viewer access require MFA, or is SSO token sufficient? | **Resolved** — MFA is optional per user; Org Admin can enforce org-wide; external MFA systems connectable via OIDC/RADIUS |
| OQ-RBAC-7 | Should `policy:write` scope be available on API keys at all, or reserved for UI-only actions? | **Resolved** — Policy editing is UI-only; `policy:write` API scope removed entirely |
