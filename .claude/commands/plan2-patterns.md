# Plan 2 Pattern Reference: Finding Workflow Implementation Patterns

Use this as a reference when implementing Plan 2 (Finding Workflow) tasks. These patterns ensure consistency across all agents.

## Backend Route Pattern

Every new route MUST follow this exact structure:

```python
from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(tags=["findings"])

@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingStatusResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
        Role.TEAM_MANAGER, Role.DEVELOPER,
    ))],
)
async def change_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingStatusResponse:
    """Change a finding's status. RBAC: varies by target status (see D14/D17)."""
    # Fine-grained RBAC check inside (role allows endpoint, but specific status may be restricted)
    return await finding_status_service.change_status(
        finding_id=finding_id,
        new_status=body.status,
        reason=body.reason,
        actor=user,
        session=session,
    )
```

**Key points:**
- `dependencies=[Depends(require_role(...))]` for coarse RBAC (who can call this endpoint at all)
- `user: AuthenticatedUser = Depends(get_current_user)` for fine-grained checks inside the handler
- `session: AsyncSession = Depends(get_session)` for DB access
- Service does the business logic, route is thin

## Backend Service Pattern

```python
class FindingStatusService:
    async def change_status(self, finding_id, new_status, reason, actor, session):
        # 1. Load finding
        # 2. Validate transition (see VALID_TRANSITIONS below)
        # 3. Check fine-grained RBAC
        # 4. Update finding
        # 5. Record history (FindingStatusHistory)
        # 6. Log audit (audit_service.log(...))
        # 7. Return updated finding

finding_status_service = FindingStatusService()  # module singleton
```

## Finding Status Transitions (D14)

```
VALID_TRANSITIONS = {
    "open":        ["in_review", "in_progress", "resolved", "risk_accepted", "false_positive"],
    "in_review":   ["open", "in_progress", "resolved", "risk_accepted", "false_positive"],
    "in_progress": ["open", "in_review", "resolved"],
    "resolved":    ["open"],  # reopen only
    "risk_accepted": ["open"],  # reversal with mandatory reason
    "false_positive": ["open"],  # reversal with mandatory reason
}
```

**Mandatory justification:**
- `risk_accepted` requires: reason, reason_category (compensating_control|low_impact|migration_planned|business_exception), review_date
- `false_positive` requires: reason (freetext)
- Reversal from RA/FP → Open requires: reason explaining why acceptance is revoked

## RBAC Matrix for Status Changes (D17)

```python
STATUS_ROLE_MAP = {
    "open":            [Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER, Role.TEAM_MANAGER, Role.DEVELOPER],
    "in_review":       [Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER, Role.TEAM_MANAGER, Role.DEVELOPER],
    "in_progress":     [Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER, Role.TEAM_MANAGER, Role.DEVELOPER],
    "resolved":        [Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER],
    "risk_accepted":   [Role.ORG_ADMIN, Role.SECURITY_MANAGER],
    "false_positive":  [Role.ORG_ADMIN, Role.SECURITY_MANAGER],
}
```

DEV can only change status on findings assigned to them.

## Frontend Component Pattern

```tsx
export function FindingStatusBadge({ status }: { status: string }): React.ReactElement {
  const variantMap: Record<string, string> = {
    open: 'badge-red',
    in_review: 'badge-amber',
    in_progress: 'badge-blue',
    resolved: 'badge-green',
    risk_accepted: 'badge-purple',
    false_positive: 'badge-gray',
  };
  return <span className={`badge ${variantMap[status] ?? 'badge-gray'}`}>{formatStatus(status)}</span>;
}
```

## Frontend API Hook Pattern

```tsx
export function useChangeStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ findingId, status, reason }: StatusChangeParams) =>
      apiClient(`/findings/${findingId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status, reason }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Status updated', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to update status', description: err.message, variant: 'error' });
    },
  });
}
```

## MSW Handler Pattern

Every new backend endpoint MUST get a corresponding MSW handler in `frontend/src/mocks/handlers.ts`:

```typescript
// Add to handlers array
http.patch('/api/v1/findings/:findingId/status', async ({ request, params }) => {
  const body = await request.json() as { status: string; reason?: string };
  return HttpResponse.json({
    id: params.findingId,
    status: body.status,
    updatedAt: new Date().toISOString(),
  });
}),
```

## Audit Logging Pattern

Every state-changing operation must log via audit service:

```python
from app.services.audit_service import audit_service

await audit_service.log(
    action_type="finding.status_change",
    actor_id=actor.id,
    org_id=actor.org_id,
    target_type="finding",
    target_id=finding_id,
    details={"old_status": old, "new_status": new, "reason": reason},
    project_id=finding.project_id,
    session=session,
)
```

## Test Pattern

```python
@pytest.mark.asyncio
async def test_change_status_open_to_in_review():
    service = FindingStatusService()
    session = AsyncMock()

    # Mock finding lookup
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.status = "open"
    finding.project_id = uuid.uuid4()
    finding.org_id = uuid.uuid4()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = finding
    session.execute = AsyncMock(return_value=mock_result)

    actor = MagicMock()
    actor.id = uuid.uuid4()
    actor.org_id = finding.org_id
    actor.role = "security_engineer"

    result = await service.change_status(
        finding_id=finding.id,
        new_status="in_review",
        actor=actor,
        session=session,
    )

    assert finding.status == "in_review"
```

## Doc Update Checklist (per task)

After implementing each task:
- [ ] RBAC-REFERENCE.md — add new endpoint's role matrix
- [ ] MSW handlers — add mock for new endpoint
- [ ] UX-AUDIT-FINDINGS.md — mark resolved items as DONE
- [ ] Run `/openapi-sync` if endpoint shape differs from spec
