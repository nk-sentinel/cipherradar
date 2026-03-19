import json
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cbom import CBOMDocument


class PostgresCBOMStore:
    """CBOM store backed by PostgreSQL JSONB column (ADR-012).

    For development and early-stage deployments (< 10 GB total CBOM storage,
    < 500 scans/day). The storage URI format is ``postgres://<document_id>``.

    Production deployments should use S3CBOMStore instead.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store(self, scan_id: str, cbom_json: bytes) -> str:
        """Store CBOM JSON in the cbom_documents table's JSONB column."""
        doc_id = uuid.uuid4()
        parsed = json.loads(cbom_json)

        document = CBOMDocument(
            id=doc_id,
            scan_id=uuid.UUID(scan_id),
            storage_uri=f"postgres://{doc_id}",
            spec_version=parsed.get("specVersion", "1.7"),
            serial_number=parsed.get("serialNumber"),
            cbom_json=parsed,
        )
        self._session.add(document)
        await self._session.flush()
        return document.storage_uri

    async def retrieve(self, storage_uri: str) -> bytes:
        """Retrieve CBOM JSON from the JSONB column by storage URI."""
        stmt = select(CBOMDocument).where(CBOMDocument.storage_uri == storage_uri)
        result = await self._session.execute(stmt)
        document = result.scalar_one_or_none()

        if document is None:
            msg = f"CBOM document not found: {storage_uri}"
            raise FileNotFoundError(msg)

        if document.cbom_json is None:
            msg = f"CBOM document has no inline JSON (may be stored externally): {storage_uri}"
            raise FileNotFoundError(msg)

        return json.dumps(document.cbom_json).encode("utf-8")

    async def delete(self, storage_uri: str) -> None:
        """Delete a CBOM document by its storage URI."""
        stmt = select(CBOMDocument).where(CBOMDocument.storage_uri == storage_uri)
        result = await self._session.execute(stmt)
        document = result.scalar_one_or_none()

        if document is not None:
            await self._session.delete(document)
            await self._session.flush()
