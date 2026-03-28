# Phase 6 — Enterprise Identity & SSO

> **Version:** v1 | **Date:** 2026-03-22
> **Status:** Planning
> **Depends on:** Phase 4.5 (auth_source foundation)

---

## Overview

Phase 6 delivers enterprise identity integration: SSO authentication (SAML 2.0, OIDC), automated user provisioning (SCIM 2.0), and identity provider group-to-role mapping. This phase makes CipherRadar deployable in enterprises that mandate centralized identity management.

---

## Milestones

### M1: SAML 2.0 SSO (2–3 weeks)

**Goal:** Users authenticate via corporate IdP (Okta, Azure AD/Entra, ADFS, OneLogin, PingIdentity)

**Deliverables:**
- SAML 2.0 Service Provider (SP) implementation in FastAPI
- SP metadata endpoint (`/api/v1/auth/saml/metadata`)
- ACS (Assertion Consumer Service) endpoint for SAML response processing
- SLO (Single Logout) support
- Admin UI: SAML configuration page (IdP metadata URL, Entity ID, Certificate, Attribute mapping)
- IdP-initiated and SP-initiated login flows
- JIT (Just-In-Time) user provisioning from SAML assertion attributes
- `auth_source` set to 'saml' for SAML-provisioned users

**Configuration (Admin > Identity > SAML):**
- IdP Metadata URL or XML upload
- Entity ID
- ACS URL (auto-generated)
- Certificate for signature validation
- Attribute mapping: email, name, role, groups
- Test connection button

### M2: OIDC SSO (1–2 weeks)

**Goal:** Alternative SSO via OpenID Connect (Azure AD, Okta, Google Workspace, Keycloak)

**Deliverables:**
- OIDC Relying Party implementation
- Authorization Code Flow with PKCE
- Discovery endpoint support (`.well-known/openid-configuration`)
- Token validation (ID token, access token)
- Admin UI: OIDC configuration page (Client ID, Client Secret, Issuer URL, Scopes)
- `auth_source` set to 'oidc' for OIDC-provisioned users

**Configuration (Admin > Identity > OIDC):**
- Issuer URL (auto-discovers endpoints)
- Client ID + Client Secret
- Scopes (default: openid, profile, email)
- Claim mapping: email, name, groups
- Test connection button

### M3: SCIM 2.0 Provisioning (2–3 weeks)

**Goal:** Automated user lifecycle management from IdP

**Deliverables:**
- SCIM 2.0 server endpoints:
  - `GET /scim/v2/Users` — list users
  - `POST /scim/v2/Users` — create user
  - `GET /scim/v2/Users/{id}` — get user
  - `PUT /scim/v2/Users/{id}` — replace user
  - `PATCH /scim/v2/Users/{id}` — update user attributes
  - `DELETE /scim/v2/Users/{id}` — deactivate user
  - `GET /scim/v2/Groups` — list groups
  - `POST /scim/v2/Groups` — create group
  - `PATCH /scim/v2/Groups/{id}` — update group membership
- SCIM bearer token authentication for IdP → CipherRadar API calls
- User schema mapping (SCIM attributes → CipherRadar User model)
- Group schema mapping (SCIM groups → CipherRadar Groups)
- `auth_source` set to 'scim' for SCIM-provisioned users
- Admin UI: SCIM configuration page (endpoint URL, bearer token generation)
- Deprovisioning: SCIM DELETE → user disabled in CipherRadar (soft delete, audit logged)

### M4: Group-to-Role Mapping (1 week)

**Goal:** AD/IdP groups automatically determine CipherRadar roles

**Deliverables:**
- Admin UI: Group mapping configuration
  - Map IdP group name → CipherRadar role
  - e.g., `AD:Security-Engineers` → `security-engineer`
  - e.g., `AD:Compliance-Team` → `compliance-auditor`
  - e.g., `AD:CipherRadar-Admins` → `org-admin`
- Default role for unmapped groups (configurable, default: `developer`)
- Override support: admin can pin a user's role to override group mapping
- Sync behavior: role re-evaluated on each login (SSO) or SCIM push
- Conflict resolution: if user in multiple groups, highest-privilege role wins (configurable)

### M5: MFA (1–2 weeks)

**Goal:** Multi-factor authentication for local auth users

**Deliverables:**
- TOTP (Time-based One-Time Password) support via authenticator apps (Google Authenticator, Authy, etc.)
- MFA setup flow: QR code display, verify first code, generate backup codes
- MFA enforcement: org-level policy (optional / required for all / required for admin roles)
- Recovery: backup codes (10 one-time codes), admin can reset MFA for a user
- Profile UI: Enable/Disable MFA, view backup codes, regenerate codes
- Login flow: after password verification, prompt for TOTP code
- When SSO is configured: MFA hidden in CipherRadar (enforced by IdP)

### M6: Login Page Evolution (3–5 days)

**Goal:** Login page adapts to configured identity providers

**Deliverables:**
- Dynamic login page based on org configuration:
  - Local only: email + password form
  - SAML configured: "Sign in with [IdP Name]" button + optional local fallback
  - OIDC configured: "Sign in with [Provider]" button + optional local fallback
  - Multiple IdPs: button per provider
- Hide SSO buttons when not configured (no more "not configured" alerts)
- "Forgot Password" link (local auth only)
- MFA prompt after password step (local auth with MFA enabled)
- Branding: org logo + name on login page (from org settings)

---

## Success Criteria

- SAML SSO tested with: Okta, Azure AD/Entra, ADFS
- OIDC SSO tested with: Azure AD, Okta, Google Workspace, Keycloak
- SCIM provisioning tested with: Azure AD, Okta
- User provisioned via SCIM can log in via SSO within 60 seconds of AD group assignment
- User deprovisioned via SCIM cannot access CipherRadar within 5 minutes
- Group-to-role mapping: < 5% incorrect role assignment rate
- MFA: TOTP verified with Google Authenticator and Authy

---

## Dependencies

- Phase 4.5 D6: `auth_source` field on User model (foundation)
- Phase 4.5 D6: conditional Profile UI based on auth_source
- Redis: session management for SSO tokens
- HTTPS required: SAML assertions must be encrypted in transit

---

## Effort Estimate

| Milestone | Effort | Dependencies |
|---|---|---|
| M1: SAML 2.0 | 2–3 weeks | None |
| M2: OIDC | 1–2 weeks | None (can parallel M1) |
| M3: SCIM 2.0 | 2–3 weeks | M1 or M2 (needs SSO for full flow) |
| M4: Group-to-Role | 1 week | M3 |
| M5: MFA | 1–2 weeks | None (can parallel M1-M4) |
| M6: Login Page | 3–5 days | M1, M2 |
| **Total** | **8–12 weeks** | |

---

## Change Log

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-22 | Initial plan from UX audit session |
