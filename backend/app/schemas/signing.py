"""Pydantic schemas for CBOM signing endpoints."""

from pydantic import BaseModel


class SigningVerifyResponse(BaseModel):
    """Response from CBOM signature verification."""

    verified: bool
    signature: str = ""
    rekor_log_id: str = ""
    error: str = ""
