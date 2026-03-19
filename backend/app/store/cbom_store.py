from typing import Protocol


class CBOMStore(Protocol):
    """Storage abstraction for CBOM JSON documents (ADR-012).

    Two implementations exist:
    - PostgresCBOMStore: stores in JSONB column (dev/early stage)
    - S3CBOMStore: stores in MinIO/S3 (production)

    Switching between them is a configuration change, not a code change.
    """

    async def store(self, scan_id: str, cbom_json: bytes) -> str:
        """Store a CBOM document and return a storage URI."""
        ...

    async def retrieve(self, storage_uri: str) -> bytes:
        """Retrieve a CBOM document by its storage URI."""
        ...

    async def delete(self, storage_uri: str) -> None:
        """Delete a CBOM document by its storage URI."""
        ...
