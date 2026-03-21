"""Pydantic schemas for CBOM signing endpoints."""

from app.schemas.base import CamelCaseModel


class SigningVerifyResponse(CamelCaseModel):
    """Response from CBOM signature verification."""

    verified: bool
    signature: str = ""
    rekor_log_id: str = ""
    error: str = ""
