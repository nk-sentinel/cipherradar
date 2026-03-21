"""Assets API — paginated, filterable crypto asset inventory across all projects."""

import os

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.asset import AssetItem, AssetListResponse
from app.services.group_service import get_accessible_project_ids

router = APIRouter(prefix="/assets", tags=["assets"])

# File extension to language mapping
_EXT_TO_LANG: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".cpp": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".m": "Objective-C",
}


def _infer_language(file_path: str) -> str:
    """Infer programming language from a file extension."""
    _, ext = os.path.splitext(file_path)
    return _EXT_TO_LANG.get(ext.lower(), "Unknown")


@router.get("", response_model=AssetListResponse)
async def list_assets(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    search: str | None = Query(default=None, description="Search by asset name"),
    type: str | None = Query(default=None, description="Filter by asset type (algorithm/protocol/key/certificate)"),
    language: str | None = Query(default=None, description="Filter by language"),
    quantum_status: str | None = Query(default=None, description="Filter by quantum status"),
    compliance: str | None = Query(default=None, description="Filter by compliance status"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> AssetListResponse:
    """List crypto assets across all accessible projects with filtering and pagination."""
    project_ids = await get_accessible_project_ids(session, user)
    if not project_ids:
        return AssetListResponse(items=[], total=0, page=page, page_size=page_size)

    # Base query joining findings with projects
    stmt = (
        select(
            Finding.id,
            Finding.name,
            Finding.asset_type,
            Finding.location_file,
            Finding.location_line,
            Finding.quantum_status,
            Finding.properties,
            Project.name.label("project_name"),
        )
        .join(Project, Finding.project_id == Project.id)
        .where(Finding.project_id.in_(project_ids))
    )

    # Apply filters
    if search:
        stmt = stmt.where(Finding.name.ilike(f"%{search}%"))
    if type:
        stmt = stmt.where(Finding.asset_type == type)
    if quantum_status:
        stmt = stmt.where(Finding.quantum_status == quantum_status)

    # Count total before pagination
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total = total_result.scalar() or 0

    # Apply pagination
    offset = (page - 1) * page_size
    stmt = stmt.order_by(Finding.name).offset(offset).limit(page_size)

    result = await session.execute(stmt)
    rows = result.fetchall()

    items = []
    for row in rows:
        file_path = row[3]
        lang = _infer_language(file_path)

        # Post-filter by language (inferred from file extension)
        if language and lang.lower() != language.lower():
            continue

        # Extract compliance from properties if available
        props = row[6] or {}
        compliance_status = props.get("compliance", "unknown")

        # Post-filter by compliance
        if compliance and compliance_status.lower() != compliance.lower():
            continue

        items.append(
            AssetItem(
                id=str(row[0]),
                name=row[1],
                type=row[2],
                language=lang,
                repo=row[7],
                location=f"{file_path}:{row[4]}",
                quantum_status=row[5],
                compliance=compliance_status,
            )
        )

    return AssetListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )
