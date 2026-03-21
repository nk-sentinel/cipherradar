"""User API endpoints: organisation membership."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.schemas.user_orgs import UserOrg, UserOrgList

router = APIRouter(prefix="/user", tags=["user"])


@router.get("/orgs", response_model=UserOrgList)
async def list_user_orgs(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> UserOrgList:
    """List organisations the current user belongs to."""
    result = await session.execute(
        text(
            "SELECT o.id, o.name, o.plan, u.role "
            "FROM users u "
            "JOIN organisations o ON u.org_id = o.id "
            "WHERE u.id = :user_id"
        ),
        {"user_id": user.user_id},
    )
    rows = result.fetchall()

    items = [
        UserOrg(
            id=str(row[0]),
            name=row[1],
            plan=row[2],
            role=row[3],
        )
        for row in rows
    ]
    return UserOrgList(items=items)
