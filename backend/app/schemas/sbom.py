import uuid  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import BaseModel, Field


class SBOMComponent(BaseModel):
    """A single component extracted from an SBOM."""

    name: str
    version: str | None = None
    purl: str | None = Field(default=None, description="Package URL (purl)")
    type: str = Field(default="library", description="Component type (library, framework, etc.)")


class SBOMUploadResponse(BaseModel):
    """Response after SBOM upload."""

    sbom_id: uuid.UUID
    project_id: uuid.UUID
    format: str = Field(description="cyclonedx or spdx")
    components_count: int = Field(ge=0)
    storage_uri: str


class SBOMCBOMLink(BaseModel):
    """A link between an SBOM component and CBOM findings."""

    library_name: str
    library_version: str | None = None
    purl: str | None = None
    crypto_findings: list[str] = Field(
        default_factory=list,
        description="Names of cryptographic findings associated with this library",
    )
    findings_count: int = Field(default=0, ge=0)


class SBOMCBOMLinkResponse(BaseModel):
    """Response for SBOM-CBOM linkage."""

    project_id: uuid.UUID
    total_libraries: int = Field(ge=0)
    linked_libraries: int = Field(ge=0, description="Libraries with at least one crypto finding")
    links: list[SBOMCBOMLink]
