# Plan 4 Pattern Reference: User & Auth Implementation Patterns

Use this as a reference when implementing Plan 4 (User & Auth) tasks. Extends plan2-patterns.md — read that first for base route/service/test/RBAC patterns.

## Password Hashing Pattern

Existing pattern in `backend/app/api/v1/auth.py`:
```python
import bcrypt as _bcrypt_lib

# Hash
hashed = _bcrypt_lib.hashpw(password.encode(), _bcrypt_lib.gensalt()).decode()

# Verify
_bcrypt_lib.checkpw(password.encode(), hashed_password.encode())
```

## API Key Generation Pattern

Existing pattern in `backend/app/auth/api_keys.py`:
```python
import secrets
import hashlib

raw = secrets.token_urlsafe(32)  # "cr_sk_abc123..."
prefix = raw[:12]                 # shown to user after creation
key_hash = hashlib.sha256(raw.encode()).hexdigest()  # stored in DB
```

Key shown once at creation, then only prefix visible. Stored as SHA-256 hash.

## User Lifecycle State Machine (D9)

```
Active → Disabled (soft-lock, reversible)
Disabled → Active (re-enable)
Disabled → Deleted (soft-delete, 30-day grace)
Deleted → Restored (within 30 days)
After 30 days → Hard purge (irreversible)
```

**Constraints:**
- Cannot disable last Org Admin
- Cannot delete active user (must disable first)
- Delete confirmation requires typing user's email
- API keys suspended on disable, unsuspended on re-enable
- API keys with scopes exceeding new role are auto-revoked on downgrade

## Role Resolution (D12)

```python
def get_effective_role(user_role: str, group_role: str | None) -> str:
    """Return the higher-privilege role. user_role is global floor."""
    if group_role is None:
        return user_role
    ROLE_RANK = {
        "guest": 0, "developer": 1, "compliance_auditor": 2,
        "team_manager": 3, "security_engineer": 4,
        "security_manager": 5, "org_admin": 6,
    }
    return user_role if ROLE_RANK.get(user_role, 0) >= ROLE_RANK.get(group_role, 0) else group_role
```

Phase 4.5: `user_group.role` is nullable. Everything uses global role since group roles aren't set yet. But the `get_effective_role()` function must exist and be used by all permission checks.

## User Creation RBAC (D10)

| Creator Role | Can Assign |
|---|---|
| Org Admin | All 7 roles |
| Security Manager | SE, TM, CA, DEV, Guest only |
| All others | Cannot create users |

## Reset Token Pattern (D30)

```python
import secrets
from datetime import datetime, timedelta, timezone

token = secrets.token_urlsafe(32)
expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
# Store hash of token in DB, send raw token in email link
```

## Frontend — User Management Table Pattern

```tsx
// User row with inline role dropdown
<select
  value={user.role}
  onChange={(e) => changeRole(user.id, e.target.value)}
  disabled={!canEditRole(currentUser, user)}
>
  {allowedRoles(currentUser.role).map(r => <option key={r}>{r}</option>)}
</select>
```

## Frontend — User Detail Drawer Pattern

Side drawer opens on user row click. Read-only in Phase 4.5:
- Profile info, role, auth source, last active
- Group memberships with project list
- API key count
- Quick actions (disable, reset password) — conditional on auth_source

## Conditional Rendering by Auth Source (D6)

```tsx
{user.authSource === 'local' && (
  <>
    <PasswordChangeForm />
    <MFASection disabled tooltip="Available in Phase 6" />
  </>
)}
{user.authSource !== 'local' && (
  <ManagedByIdP provider={user.authSource} />
)}
```

## Test Pattern — Password/Auth

```python
@pytest.mark.asyncio
async def test_change_password_success():
    service = PasswordService()
    session = AsyncMock()

    user = MagicMock()
    user.hashed_password = bcrypt.hashpw(b"oldpass", bcrypt.gensalt()).decode()

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute = AsyncMock(return_value=result_mock)

    await service.change_password(
        user_id=user.id,
        current_password="oldpass",
        new_password="Newpass123!",
        session=session,
    )

    # Verify password was updated
    assert user.hashed_password != bcrypt.hashpw(b"oldpass", bcrypt.gensalt()).decode()
```
