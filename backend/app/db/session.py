from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_engine = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_engine(database_url: str) -> None:
    """Create the async engine and session factory.

    Called once during application lifespan startup.
    """
    global _engine, _async_session_factory  # noqa: PLW0603
    _engine = create_async_engine(
        database_url,
        echo=False,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )
    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def dispose_engine() -> None:
    """Dispose the async engine. Called during application shutdown."""
    global _engine, _async_session_factory  # noqa: PLW0603
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """Dependency that yields an async session.

    Usage in FastAPI endpoints::

        @router.get("/example")
        async def example(session: AsyncSession = Depends(get_session)):
            ...
    """
    if _async_session_factory is None:
        msg = "Database engine not initialised. Call init_engine() first."
        raise RuntimeError(msg)
    async with _async_session_factory() as session:
        yield session  # type: ignore[misc]
