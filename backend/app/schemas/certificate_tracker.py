"""Certificate tracker schemas — certificate expiry tracking from findings (D23)."""

from __future__ import annotations

import uuid
from datetime import datetime

from app.schemas.base import CamelCaseModel


class CertificateEntry(CamelCaseModel):
    """A single certificate extracted from a finding with expiry status."""

    id: uuid.UUID
    subject: str
    issuer: str
    not_after: datetime
    status_color: str  # green, amber, red, black
    days_remaining: int
    project_name: str
    project_id: uuid.UUID
    file_path: str

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class CertificateTrackerResponse(CamelCaseModel):
    """Paginated certificate tracker response."""

    items: list[CertificateEntry]
    total: int
    page: int
    per_page: int
