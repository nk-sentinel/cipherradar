# Fix Round Patterns: Post-Implementation Bug Fix Standards

Use when fixing Phase 4.5 UI audit findings. Read plan2-patterns.md first for base patterns.

## Logging Standard

Every fix that touches a service or component must add appropriate logging:

**Backend (Python):**
```python
import logging
logger = logging.getLogger(__name__)

# Business events: INFO
logger.info("Finding status changed", extra={"extra_fields": {"finding_id": str(id), "action": "status_change"}})

# Warnings: WARNING
logger.warning("RBAC denied", extra={"extra_fields": {"user_id": str(uid), "required_role": "sm", "actual_role": role}})

# Errors: ERROR
logger.error("Failed to create Jira issue", extra={"extra_fields": {"finding_id": str(id)}}, exc_info=True)
```

**Frontend (console):**
```typescript
// Only log errors and warnings, not info in production
console.error('[CipherRadar] Failed to load findings:', error.message);
console.warn('[CipherRadar] RBAC: insufficient role for action');
```

## RBAC Guard Pattern

Every page that needs role restriction:
```tsx
import { RequireRole } from '@/components/guards/RequireRole';

export function ProtectedPage() {
  return (
    <RequireRole roles={['org-admin', 'security-manager']} fallback={<AccessDenied />}>
      <PageContent />
    </RequireRole>
  );
}
```

**Always provide a fallback UI** — never render blank for unauthorized users.

## Confirmation Dialog Pattern

For destructive actions (delete, disable, role change):
```tsx
const [confirmOpen, setConfirmOpen] = useState(false);
const [confirmText, setConfirmText] = useState('');

// In JSX:
{confirmOpen && (
  <div className="modal-overlay">
    <div className="modal">
      <p>Type "<strong>{user.email}</strong>" to confirm deletion:</p>
      <input value={confirmText} onChange={e => setConfirmText(e.target.value)} />
      <button disabled={confirmText !== user.email} onClick={handleDelete}>Delete</button>
      <button onClick={() => setConfirmOpen(false)}>Cancel</button>
    </div>
  </div>
)}
```

## Justification Modal Pattern

For FP/RA transitions:
```tsx
{justificationOpen && (
  <div className="modal-overlay">
    <div className="modal">
      <h3>Justification Required</h3>
      {isRA && <select>{reasonCategories}</select>}
      <textarea required placeholder="Explain why..." />
      {isRA && <input type="date" required />}
      <button disabled={!justification}>Submit</button>
    </div>
  </div>
)}
```

## Page Removal Pattern (for rejected features)

1. Remove route from `router.tsx`
2. Remove sidebar entry from `Sidebar.tsx`
3. Remove page key from `roles.ts` PAGE_ACCESS
4. Keep the component file (don't delete — may be repurposed)
5. Update any links pointing to removed route

## Naming Fix Pattern

When renaming a page title:
- Change the `<h1>` in the page component
- Change the sidebar label in `Sidebar.tsx`
- Keep the URL path unchanged (breaking change)
- Update any breadcrumb references

## After Every Fix

- Verify `npm run build` passes (no TS errors)
- Commit with descriptive message referencing the finding IDs
- No co-author tags
