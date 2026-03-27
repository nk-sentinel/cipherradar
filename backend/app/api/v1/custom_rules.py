"""Custom rule management endpoints (D27).

Routes: POST/GET /admin/rules, PUT/DELETE /admin/rules/{id},
POST /admin/rules/{id}/test, GET /rules/delta?since=.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.custom_rule import (
    CustomRuleCreateRequest,
    CustomRuleDryRunRequest,
    CustomRuleDryRunResponse,
    CustomRuleForkRequest,
    CustomRuleListResponse,
    CustomRuleResponse,
    CustomRuleUpdateRequest,
    DeltaSyncResponse,
)
from app.services.custom_rule_service import custom_rule_service

router = APIRouter(tags=["custom-rules"])

_oa_dep = require_role(Role.ORG_ADMIN)
_read_dep = require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER)


# ---------------------------------------------------------------------------
# POST /admin/rules — upload new rule (OA)
# ---------------------------------------------------------------------------


@router.post(
    "/admin/rules",
    response_model=CustomRuleResponse,
    status_code=201,
    dependencies=[Depends(_oa_dep)],
)
async def create_custom_rule(
    body: CustomRuleCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CustomRuleResponse:
    """Upload a new custom detection rule. OA only."""
    try:
        result = await custom_rule_service.upload(
            name=body.name,
            description=body.description,
            language=body.language,
            pattern_type=body.pattern_type,
            pattern=body.pattern,
            severity=body.severity,
            actor=user,
            session=session,
        )
        await session.commit()
        return CustomRuleResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /admin/rules/fork — fork a built-in rule (OA)
# ---------------------------------------------------------------------------


@router.post(
    "/admin/rules/fork",
    response_model=CustomRuleResponse,
    status_code=201,
    dependencies=[Depends(_oa_dep)],
)
async def fork_builtin_rule(
    body: CustomRuleForkRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CustomRuleResponse:
    """Fork a built-in rule into a custom org copy. OA only."""
    try:
        result = await custom_rule_service.fork(
            builtin_id=body.builtin_id,
            actor=user,
            session=session,
        )
        await session.commit()
        return CustomRuleResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /admin/rules — list custom rules with filters
# ---------------------------------------------------------------------------


@router.get(
    "/admin/rules",
    response_model=CustomRuleListResponse,
    dependencies=[Depends(_read_dep)],
)
async def list_custom_rules(
    language: str | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    pattern_type: str | None = Query(default=None),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CustomRuleListResponse:
    """List custom rules with optional filters. OA, SM, SE."""
    rules = await custom_rule_service.list_rules(
        actor=user,
        session=session,
        language=language,
        enabled=enabled,
        pattern_type=pattern_type,
    )
    return CustomRuleListResponse(
        items=[CustomRuleResponse(**r) for r in rules],
        total=len(rules),
    )


# ---------------------------------------------------------------------------
# PUT /admin/rules/{id} — update rule (OA)
# ---------------------------------------------------------------------------


@router.put(
    "/admin/rules/{rule_id}",
    response_model=CustomRuleResponse,
    dependencies=[Depends(_oa_dep)],
)
async def update_custom_rule(
    rule_id: uuid.UUID,
    body: CustomRuleUpdateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CustomRuleResponse:
    """Update a custom rule. OA only."""
    try:
        result = await custom_rule_service.update(
            rule_id=rule_id,
            actor=user,
            session=session,
            name=body.name,
            description=body.description,
            pattern=body.pattern,
            severity=body.severity,
            enabled=body.enabled,
        )
        await session.commit()
        return CustomRuleResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# DELETE /admin/rules/{id} — delete rule (OA)
# ---------------------------------------------------------------------------


@router.delete(
    "/admin/rules/{rule_id}",
    dependencies=[Depends(_oa_dep)],
)
async def delete_custom_rule(
    rule_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Delete a custom rule. OA only."""
    try:
        result = await custom_rule_service.delete(
            rule_id=rule_id,
            actor=user,
            session=session,
        )
        await session.commit()
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /admin/rules/{id}/test — dry run (OA, SM, SE)
# ---------------------------------------------------------------------------


@router.post(
    "/admin/rules/{rule_id}/test",
    response_model=CustomRuleDryRunResponse,
    dependencies=[Depends(_read_dep)],
)
async def test_custom_rule(
    rule_id: uuid.UUID,
    body: CustomRuleDryRunRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CustomRuleDryRunResponse:
    """Dry-run a custom rule against test code. OA, SM, SE."""
    try:
        result = await custom_rule_service.dry_run(
            rule_id=rule_id,
            test_code=body.test_code,
            actor=user,
            session=session,
        )
        return CustomRuleDryRunResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /rules/delta?since= — delta sync for CLI
# ---------------------------------------------------------------------------


@router.get(
    "/rules/delta",
    response_model=DeltaSyncResponse,
    dependencies=[Depends(_read_dep)],
)
async def delta_sync_rules(
    since: str = Query(..., description="ISO 8601 timestamp"),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> DeltaSyncResponse:
    """Get rules modified since a timestamp (for CLI delta sync)."""
    try:
        since_dt = datetime.fromisoformat(since)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid timestamp format: {since}",
        ) from exc

    if since_dt.tzinfo is None:
        since_dt = since_dt.replace(tzinfo=UTC)

    rules = await custom_rule_service.delta_sync(
        since=since_dt,
        actor=user,
        session=session,
    )
    return DeltaSyncResponse(
        items=[CustomRuleResponse(**r) for r in rules],
        total=len(rules),
    )
