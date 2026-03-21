import uuid

from pydantic import Field

from app.schemas.base import CamelCaseModel


class CodeSnippet(CamelCaseModel):
    """Source code context around a finding."""

    start_line: int
    highlight_lines: list[int] = Field(default_factory=list)
    lines: list[str] = Field(default_factory=list)


class FindingResponse(CamelCaseModel):
    """Response schema for a single cryptographic finding."""

    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    severity: str
    file: str
    line: int
    title: str
    algorithm: str | None = None
    quantum_status: str
    detection_pass: int = Field(default=1)
    rule_id: str
    confidence: str
    asset_type: str
    code: CodeSnippet | None = None
    remediation: str | None = None

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class FindingListResponse(CamelCaseModel):
    """Paginated list of findings."""

    items: list[FindingResponse]
    total: int
    page: int
    per_page: int
