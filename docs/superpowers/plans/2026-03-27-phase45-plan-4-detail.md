# Phase 4.5 — Plan 4: User & Auth — Detailed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** User lifecycle, API keys, password management, role resolution, login improvements, break-glass recovery.

**Decisions:** D6, D7, D9, D10, D11, D12, D30

**Depends on (Plan 1):** User model (auth_source, disabled_at, last_active_at), ApiKey model, UserGroup model (role column), pagination_service, audit_service, factories.

---

## Agent Assignment

| Agent | Tasks |
|---|---|
| **Backend Auth** | 4.1, 4.2, 4.4, 4.6, 4.7, 4.9 |
| **Frontend Auth** | 4.3, 4.5, 4.8 |
| **E2E + Security** | 4.10, 4.11 |

Backend + Frontend parallel. E2E + Security after both.

---

## Task 4.1: Backend — Password Management (D6)

**Create:**
- `backend/app/services/password_service.py` — `change_password(user_id, current, new, session)`, `admin_reset(user_id, actor, session)` generates temp password or reset token
- `backend/app/schemas/password.py` — `PasswordChange(current_password, new_password)`, `PasswordReset(token, new_password)`, `ForgotPassword(email)`
- `backend/app/api/v1/password.py` — routes below
- `backend/tests/services/test_password_service.py`
- `backend/tests/api/test_password.py`

**Routes:**
- `PUT /api/v1/auth/password` — self change. Roles: all (auth_source=local only).
- `PUT /api/v1/admin/users/{user_id}/reset-password` — admin reset. Roles: OA.
- `POST /api/v1/auth/forgot-password` — send reset email. Public.
- `POST /api/v1/auth/reset-password` — reset via token. Public.

**Tests:** test_change_password_success, test_change_password_wrong_current, test_change_password_validation (min 8 chars), test_admin_reset, test_forgot_password_sends_email (mock aiosmtplib), test_reset_with_valid_token, test_reset_with_expired_token, test_non_local_user_cannot_change_password

Commit: `feat: add password management service and routes (D6, D30)`

## Task 4.2: Backend — API Key Management (D7)

**Create:**
- `backend/app/services/api_key_service.py` — `create(user, name, scopes, expires, session)` returns raw key once, `list_own(user, session)`, `list_all(org_id, session)`, `revoke(key_id, user, session)`
- `backend/app/schemas/api_key.py` — `ApiKeyCreate(name, scopes[], expires_in_days)`, `ApiKeyResponse(id, name, prefix, scopes, created_at, last_used_at, is_active)`, `ApiKeyCreatedResponse(extends ApiKeyResponse + raw_key)`
- Modify `backend/app/api/v1/auth.py` — add key routes or create separate `backend/app/api/v1/api_keys.py`
- `backend/tests/services/test_api_key_service.py`

**Routes:**
- `POST /api/v1/auth/api-keys` — create. Roles: all except Guest. Scopes capped by role.
- `GET /api/v1/auth/api-keys` — list own (masked). Roles: all except Guest.
- `DELETE /api/v1/auth/api-keys/{key_id}` — revoke own. Roles: all except Guest.
- `GET /api/v1/admin/api-keys` — all org keys. Roles: OA (full), SM (read-only).
- `DELETE /api/v1/admin/api-keys/{key_id}` — revoke any. Roles: OA.

**Tests:** test_create_returns_raw_key_once, test_list_shows_prefix_only, test_scopes_capped_by_role, test_revoke_own, test_admin_sees_all_keys, test_admin_revoke_any, test_guest_cannot_create, test_expired_key_excluded

Commit: `feat: add API key management service and routes (D7)`

## Task 4.3: Frontend — Profile Page Overhaul (D6, D7)

**Modify:** `frontend/src/pages/Profile.tsx`
**Create:**
- `frontend/src/components/profile/PasswordChangeForm.tsx`
- `frontend/src/components/profile/ApiKeyManager.tsx`
- `frontend/src/components/profile/ApiKeyCreateModal.tsx`
- `frontend/src/api/hooks/useApiKeys.ts`
- `frontend/src/api/hooks/usePassword.ts`
- `frontend/tests/components/PasswordChangeForm.test.tsx`
- `frontend/tests/components/ApiKeyManager.test.tsx`

**PasswordChangeForm:** Current + new password fields, validation, submit. Conditional on auth_source=local. Hidden for SSO users with "Managed by [IdP]" message.

**ApiKeyManager:** Table of own keys (name, prefix, scopes, created, last used, status). Create button → modal. Revoke button per row. Key shown once in success modal with copy button.

**ApiKeyCreateModal:** Name, expiry dropdown (30/60/90/180/365/Never), scope checkboxes (capped by role).

**MFA button:** Disabled with "Available in Phase 6" tooltip.

**Tests:** test_password_form_validates, test_password_form_hidden_for_sso, test_api_key_table_renders, test_create_key_shows_raw_once, test_revoke_key

Commit: `feat: overhaul profile page — password, API keys, auth source (D6, D7)`

## Task 4.4: Backend — User Lifecycle (D9)

**Create:**
- `backend/app/services/user_lifecycle_service.py` — `change_role(user_id, new_role, actor, session)`, `disable_user(user_id, actor, session)`, `enable_user(user_id, actor, session)`, `delete_user(user_id, actor, session)`, `restore_user(user_id, actor, session)`
- `backend/app/schemas/user_lifecycle.py`
- Modify `backend/app/api/v1/admin.py` — add lifecycle routes
- `backend/tests/services/test_user_lifecycle_service.py`

**Routes:**
- `PUT /api/v1/admin/users/{user_id}/role` — Body: {role}. Roles: OA.
- `POST /api/v1/admin/users/{user_id}/disable` — Roles: OA.
- `POST /api/v1/admin/users/{user_id}/enable` — Roles: OA.
- `DELETE /api/v1/admin/users/{user_id}` — must be disabled first. Roles: OA.

**Logic:**
- Role downgrade: auto-revoke API keys whose scopes exceed new role
- Last-OA protection: cannot disable/demote last OA
- Disable: set disabled_at, suspend API keys (is_active=false)
- Enable: clear disabled_at, unsuspend API keys
- Delete: must be disabled first. Set deleted_at. 30-day grace period.
- Deletion policy from org settings (retain name vs anonymize)

**Tests:** test_change_role_success, test_change_role_downgrades_api_keys, test_cannot_demote_last_oa, test_disable_suspends_keys, test_enable_unsuspends_keys, test_delete_requires_disabled, test_delete_sets_grace_period, test_audit_log_on_lifecycle

Commit: `feat: add user lifecycle — role change, disable, delete (D9)`

## Task 4.5: Frontend — User Management Page (D9, D10, D11)

**Modify:** `frontend/src/pages/admin/UserManagement.tsx`
**Create:**
- `frontend/src/components/admin/UserCreateModal.tsx` — dual flow: invite (email) vs direct add (email+name+password+role)
- `frontend/src/components/admin/UserDetailDrawer.tsx` — side drawer on row click
- `frontend/src/api/hooks/useUserManagement.ts` — CRUD hooks
- `frontend/tests/pages/UserManagement.test.tsx`
- `frontend/tests/components/UserCreateModal.test.tsx`
- `frontend/tests/components/UserDetailDrawer.test.tsx`

**Page enhancements:**
- Server-side pagination (using `<Pagination />`)
- Search by name/email/role
- Inline role dropdown per row (OA only, capped per D10)
- Disable/enable toggle button
- Delete button (only on disabled users)
- Last Active column with stale indicators (orange >30d, red >90d)
- User detail drawer on row click

**UserCreateModal:** Toggle: "Send invite" vs "Add directly". Role dropdown capped per creator's role (D10). Group assignment at creation. Force-change on first login for direct add.

**Tests:** test_pagination_renders, test_role_dropdown_capped, test_disable_toggle, test_create_modal_dual_flow, test_drawer_opens_on_click, test_stale_indicator

Commit: `feat: overhaul user management — lifecycle, pagination, drawer (D9, D10, D11)`

## Task 4.6: Backend — Role Resolution (D12)

**Create:**
- `backend/app/services/role_resolution_service.py` — `get_effective_role(user_id, group_id, session)` returns max(global_role, group_role)
- `backend/tests/services/test_role_resolution_service.py`

**Modify:** `backend/app/auth/middleware.py` — integrate role resolution into permission checking. When a request targets a group-scoped resource, resolve effective role.

**Tests:** test_global_role_when_no_group_role, test_group_role_wins_when_higher, test_global_role_wins_when_higher, test_no_access_when_neither

Commit: `feat: add role resolution with per-group override (D12)`

## Task 4.7: Backend — Forgot Password (D30)

Already covered in Task 4.1 routes. This task adds email sending.

**Modify:** `backend/app/services/password_service.py` — wire aiosmtplib for sending reset email. Use Jinja2 template.
**Create:** `backend/app/templates/reset-password-email.html`
**Create:** `backend/tests/services/test_forgot_password_email.py`

**Tests:** test_sends_email_with_reset_link, test_no_email_if_smtp_not_configured (graceful), test_token_expires_after_1h

Commit: `feat: add forgot password email flow (D30)`

## Task 4.8: Frontend — Login Page Updates (D30, D8)

**Modify:** `frontend/src/pages/Login.tsx`
**Create:**
- `frontend/src/pages/ForgotPassword.tsx`
- `frontend/src/pages/ResetPassword.tsx`
- `frontend/tests/pages/ForgotPassword.test.tsx`

**Changes:**
- Add "Forgot Password?" link below login form
- Hide GitHub SSO and SAML SSO buttons entirely (D8 #13, #14)
- Keep error message generic: "Invalid credentials" (D30 #78)
- ForgotPassword page: email input, submit, success message
- ResetPassword page: token from URL, new password + confirm, submit

**Modify:** `frontend/src/router.tsx` — add /forgot-password, /reset-password routes

**Tests:** test_forgot_password_form, test_reset_password_form, test_sso_buttons_hidden, test_error_message_generic

Commit: `feat: update login page — forgot password, hide SSO (D30, D8)`

## Task 4.9: Backend — Break-Glass Recovery (D9)

**Create:**
- `cli/internal/cmd/admin.go` — `cradar admin reset-password --email admin@org.com` CLI command
- `cli/internal/cmd/admin_test.go`
- `backend/app/api/v1/auth.py` — add `POST /api/v1/auth/recover` endpoint for recovery key

**Recovery key:** Generated at org creation. Format: `CRADAR-RCVR-XXXX-XXXX-XXXX-XXXX`. Stored hashed. One-time use.

**Tests:** test_cli_reset_password_command, test_recovery_key_resets_password, test_recovery_key_invalidated_after_use

Commit: `feat: add break-glass admin recovery (D9)`

## Task 4.10: E2E — User & Auth Tests

**Create:** `frontend/e2e/user-auth.spec.ts`

**Scenarios:**
1. Login → change password → re-login with new password
2. Admin creates user (direct add) → new user logs in
3. Admin disables user → verify login blocked
4. Login page has forgot password link
5. Profile page accessibility scan
6. User management page accessibility scan

Commit: `test: add user & auth E2E tests`

## Task 4.11: Security — Auth Tests

**Create:** `backend/tests/security/test_auth_security.py`

**Tests:**
- RBAC matrix: every role × every new endpoint (password, API keys, user lifecycle)
- API key scope enforcement: key with scan:read cannot call admin endpoints
- Password policy: rejects short/weak passwords
- Rate limiting on login endpoint (if implemented)
- Reset token cannot be reused
- Disabled user's API keys return 401

Commit: `test: add auth security tests`

---

## Completion Criteria

- [ ] Password change/reset works for local users (D6)
- [ ] API key CRUD with scope capping (D7)
- [ ] User lifecycle: role change, disable, enable, delete with protections (D9)
- [ ] Dual user creation flow with role capping (D10)
- [ ] User table with pagination, stale indicators, drawer (D11)
- [ ] Role resolution function exists and is wired (D12)
- [ ] Forgot password email flow works (D30)
- [ ] Login page cleaned up — no SSO buttons, generic errors (D8, D30)
- [ ] Break-glass CLI command works (D9)
- [ ] E2E tests pass
- [ ] Security tests: RBAC matrix, key scope, password policy all pass
