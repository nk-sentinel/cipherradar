"""CBOM signing API endpoints — verify CBOM signatures."""

import logging
import uuid

from fastapi import APIRouter, HTTPException, status

from app.schemas.signing import SigningVerifyResponse
from app.services.signing_service import signing_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["signing"])


# ---------------------------------------------------------------------------
# GET /api/v1/cbom/{id}/verify
# ---------------------------------------------------------------------------


@router.get("/cbom/{cbom_id}/verify", response_model=SigningVerifyResponse)
async def verify_cbom(cbom_id: uuid.UUID) -> SigningVerifyResponse:
    """Verify the signature of a CBOM document.

    Only signed CBOMs are visible to Compliance Auditor / Guest roles.
    Unsigned CBOMs are hidden per RBAC.
    """
    result = await signing_service.verify_cbom(str(cbom_id))

    if not result.get("verified", False) and "error" in result:
        error = result["error"]
        if "not found" in error.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=error,
            )

    return SigningVerifyResponse(
        verified=result.get("verified", False),
        signature=result.get("signature", ""),
        rekor_log_id=result.get("rekor_log_id", ""),
        error=result.get("error", ""),
    )
