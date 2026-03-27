"""API key management endpoints (D7).

CRUD for API keys: create, list own, list all (admin), revoke.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import API_KEY_CREATOR_ROLES, Role
from app.db.session import get_session
from app.schemas.api_key import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyListItem,
    ApiKeyListResponse,
    ApiKeyRevokeResponse,
)
from app.services.api_key_service import api_key_service

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys — create
# ---------------------------------------------------------------------------


@router.post(
    "/auth/api-keys",
    response_model=ApiKeyCreateResponse,
    status_code=201,
    dependencies=[Depends(require_role(*API_KEY_CREATOR_ROLES))],
)
async def create_api_key(
    body: ApiKeyCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyCreateResponse:
    """Create a scoped API key. Returns the plaintext key once."""
    api_key, plaintext_key = await api_key_service.create(
        name=body.name,
        scopes=body.scopes,
        expires_in_days=body.expires_in_days,
        user_id=user.user_id,
        user_role=user.role,
        org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return ApiKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        key=plaintext_key,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/api-keys — list own
# ---------------------------------------------------------------------------


@router.get("/auth/api-keys", response_model=ApiKeyListResponse)
async def list_own_api_keys(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyListResponse:
    """List the current user's API keys (prefix only)."""
    keys = await api_key_service.list_own(user_id=user.user_id, session=session)
    items = [
        ApiKeyListItem(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
            revoked_at=k.revoked_at,
        )
        for k in keys
    ]
    return ApiKeyListResponse(items=items, total=len(items))


# ---------------------------------------------------------------------------
# DELETE /api/v1/auth/api-keys/{id} — revoke own
# ---------------------------------------------------------------------------


@router.delete("/auth/api-keys/{key_id}", response_model=ApiKeyRevokeResponse)
async def revoke_own_api_key(
    key_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyRevokeResponse:
    """Revoke one of the current user's API keys."""
    await api_key_service.revoke_own(
        key_id=str(key_id),
        user_id=user.user_id,
        org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return ApiKeyRevokeResponse()


# ---------------------------------------------------------------------------
# GET /api/v1/admin/api-keys — list all org keys (OA/SM)
# ---------------------------------------------------------------------------


@router.get(
    "/admin/api-keys",
    response_model=ApiKeyListResponse,
    dependencies=[Depends(require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER))],
)
async def list_all_org_api_keys(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyListResponse:
    """List all API keys in the organisation. OA/SM only."""
    keys = await api_key_service.list_all_org(org_id=user.org_id, session=session)
    items = [
        ApiKeyListItem(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
            revoked_at=k.revoked_at,
        )
        for k in keys
    ]
    return ApiKeyListResponse(items=items, total=len(items))


# ---------------------------------------------------------------------------
# DELETE /api/v1/admin/api-keys/{id} — revoke any (OA)
# ---------------------------------------------------------------------------


@router.delete(
    "/admin/api-keys/{key_id}",
    response_model=ApiKeyRevokeResponse,
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def revoke_any_api_key(
    key_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyRevokeResponse:
    """Revoke any API key in the organisation. OA only."""
    await api_key_service.revoke_any(
        key_id=str(key_id),
        org_id=user.org_id,
        actor_id=user.user_id,
        session=session,
    )
    await session.commit()
    return ApiKeyRevokeResponse()
