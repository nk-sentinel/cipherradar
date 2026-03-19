# ADR-013: Authentication Model — JWT + API Keys + Scoped Permissions

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-19 |
| **Deciders** | Architecture session |

---

## Context

The backend needs authentication for two distinct actor types: **human users** interacting via the dashboard and **machine users** (CI/CD pipelines, scripts) calling the API programmatically. The authentication model must support enterprise SSO/SAML integration, scale horizontally, and enforce fine-grained permissions aligned with the 7-role RBAC model defined in ADR-006.

---

## Decisions

### 1. Human Users — JWT + Refresh Token

Human users authenticate via email/password or SSO (SAML 2.0 / OIDC). On successful login, the backend issues:

| Token | Lifetime | Storage |
|---|---|---|
| **Access token** (JWT) | 15 minutes | Client memory only (never `localStorage`) |
| **Refresh token** | 7 days | HTTP-only secure cookie |

The access token is a signed JWT containing the user ID, org ID, active role, and scope set. The backend validates the signature and expiry on every request — no database lookup required for normal operations.

JWT revocation (e.g., password change, account deactivation) is handled via a **deny-list stored in Redis**. Entries expire after the access token's maximum lifetime (15 minutes), keeping the deny-list small.

### 2. Machine Users — Scoped API Keys

CI/CD pipelines and automation use scoped API keys instead of OAuth flows:

- Keys are prefixed for identification: `cbom_sk_...`
- Only the **SHA-256 hash** of the key is stored in the database — the plaintext key is shown once at creation and never stored
- Each key is assigned a subset of permission scopes (see below)
- Keys can be rotated, expired, and revoked independently

### 3. Permission Scopes

The following scopes are available:

| Scope | Description |
|---|---|
| `scan:read` | View scan results and history |
| `scan:write` | Trigger scans |
| `cbom:read` | Download CBOM artifacts |
| `cbom:write` | Upload/import CBOM artifacts |
| `project:read` | View project and group metadata |
| `project:write` | Create/update projects and groups |
| `report:read` | View and download compliance reports |

**`policy:write` is not available on API keys** (per resolved OQ-RBAC-7). Policy editing is a UI-only operation requiring an authenticated human session. This prevents automated policy changes without human review.

### 4. RBAC Enforcement

7 roles (Org Admin, Security Manager, Security Engineer, Team Manager, Compliance Auditor, Developer, Guest/Viewer) are enforced via middleware on every request. Roles are assigned at org, group, or project level and cascade downward through the hierarchy. The middleware resolves the user's effective role for the target resource and checks it against the endpoint's required permissions before the request handler executes.

### 5. Libraries

| Library | Purpose |
|---|---|
| `python-jose` | JWT signing and verification (RS256) |
| `passlib` | Password hashing (bcrypt, configurable rounds) |

---

## Rationale

### JWT for human users
Stateless JWT validation scales horizontally — any API instance can validate a token without shared session state. The 15-minute expiry limits the window of exposure for a leaked token. The refresh token extends session duration without issuing long-lived access tokens.

### API keys for machine users
CI/CD pipelines need a simple, scriptable authentication mechanism. API keys avoid the OAuth authorization code dance, which is impractical in headless environments. SHA-256 hashing ensures that a database breach does not expose usable credentials. The `cbom_sk_` prefix allows security teams to identify CipherRadar keys in logs and secret scanners.

### Scoped permissions
Scopes limit the blast radius of a compromised API key. A key created for CI scan submission (`scan:write`, `cbom:read`) cannot be used to modify projects or download compliance reports. The explicit exclusion of `policy:write` from API keys ensures that security policy changes always require a human in the loop.

---

## Consequences

- **Positive:** Stateless JWT scales horizontally — no shared session store for normal request validation
- **Positive:** API keys enable CI/CD integration without OAuth complexity
- **Positive:** Scoped permissions limit blast radius of compromised keys
- **Positive:** SHA-256 hashed key storage protects against database breach
- **Negative:** JWT revocation requires a Redis deny-list for immediate invalidation (adds infrastructure dependency)
- **Negative:** 7 roles with org/group/project cascading adds middleware complexity and requires thorough test coverage

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/09-rbac.md` | Authentication model details added; API key scoping documented |
| `docs/12-phase2-implementation-plan.md` | B-M2 milestone: authentication implementation scope defined |
