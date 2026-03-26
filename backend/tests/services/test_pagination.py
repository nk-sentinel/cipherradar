"""Tests for pagination framework: offset/limit calculation, total count, edge cases."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.schemas.pagination import PaginatedResponse, PaginationParams


# ---------------------------------------------------------------------------
# PaginationParams validation
# ---------------------------------------------------------------------------


class TestPaginationParams:
    """Validate PaginationParams defaults and constraints."""

    def test_defaults(self) -> None:
        params = PaginationParams()
        assert params.page == 1
        assert params.per_page == 25

    def test_custom_values(self) -> None:
        params = PaginationParams(page=3, per_page=50)
        assert params.page == 3
        assert params.per_page == 50

    def test_page_must_be_ge_1(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            PaginationParams(page=0)

    def test_per_page_must_be_ge_1(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            PaginationParams(per_page=0)

    def test_per_page_must_be_le_100(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            PaginationParams(per_page=101)

    def test_camel_case_alias(self) -> None:
        """CamelCaseModel should accept camelCase keys."""
        params = PaginationParams(**{"perPage": 10, "page": 2})
        assert params.per_page == 10
        assert params.page == 2


# ---------------------------------------------------------------------------
# PaginatedResponse
# ---------------------------------------------------------------------------


class TestPaginatedResponse:
    """Validate PaginatedResponse structure."""

    def test_basic_response(self) -> None:
        resp = PaginatedResponse[str](
            items=["a", "b"],
            total=10,
            page=1,
            per_page=25,
        )
        assert resp.items == ["a", "b"]
        assert resp.total == 10
        assert resp.page == 1
        assert resp.per_page == 25

    def test_empty_response(self) -> None:
        resp = PaginatedResponse[str](
            items=[],
            total=0,
            page=1,
            per_page=25,
        )
        assert resp.items == []
        assert resp.total == 0

    def test_camel_case_serialization(self) -> None:
        resp = PaginatedResponse[str](
            items=["x"],
            total=1,
            page=1,
            per_page=25,
        )
        data = resp.model_dump(by_alias=True)
        assert "perPage" in data
        assert "per_page" not in data


# ---------------------------------------------------------------------------
# Helper to build a mock SQLAlchemy select statement
# ---------------------------------------------------------------------------


def _make_mock_query() -> MagicMock:
    """Build a MagicMock that behaves like a SQLAlchemy select() statement.

    Supports chaining: query.with_only_columns().order_by(), query.offset(n).limit(n).
    """
    query = MagicMock()
    # .with_only_columns(func.count()).order_by(None) chain for count query
    count_chain = MagicMock()
    query.with_only_columns.return_value = count_chain
    count_chain.order_by.return_value = count_chain
    # .offset(n).limit(n) chain for data query
    offset_result = MagicMock()
    query.offset.return_value = offset_result
    offset_result.limit.return_value = MagicMock()
    return query


# ---------------------------------------------------------------------------
# paginate() function
# ---------------------------------------------------------------------------


class TestPaginate:
    """Test the paginate() utility function against mocked SQLAlchemy session."""

    @pytest.mark.asyncio
    async def test_correct_offset_limit_page_1(self) -> None:
        """Page 1, per_page=10 should use offset=0, limit=10."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        # Mock count query result
        count_result = MagicMock()
        count_result.scalar_one.return_value = 50

        # Mock data query result
        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = [{"id": i} for i in range(10)]

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await paginate(query=query, page=1, per_page=10, session=session)

        assert result.page == 1
        assert result.per_page == 10
        assert result.total == 50
        assert len(result.items) == 10

        # Verify offset(0) was called
        query.offset.assert_called_once_with(0)
        query.offset.return_value.limit.assert_called_once_with(10)

    @pytest.mark.asyncio
    async def test_correct_offset_limit_page_3(self) -> None:
        """Page 3, per_page=10 should use offset=20, limit=10."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 50

        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = [{"id": i} for i in range(10)]

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await paginate(query=query, page=3, per_page=10, session=session)

        assert result.page == 3
        assert result.per_page == 10
        assert result.total == 50
        assert len(result.items) == 10

        # Verify offset(20) was called for page 3
        query.offset.assert_called_once_with(20)
        query.offset.return_value.limit.assert_called_once_with(10)

    @pytest.mark.asyncio
    async def test_correct_total_count(self) -> None:
        """Total count should reflect the count query result."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 123

        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = [{"id": i} for i in range(25)]

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await paginate(query=query, page=1, per_page=25, session=session)

        assert result.total == 123

    @pytest.mark.asyncio
    async def test_page_beyond_total_returns_empty(self) -> None:
        """Requesting a page beyond total items should return empty items list."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 5

        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await paginate(query=query, page=100, per_page=25, session=session)

        assert result.items == []
        assert result.total == 5
        assert result.page == 100

    @pytest.mark.asyncio
    async def test_empty_results(self) -> None:
        """When the table has zero rows, should return empty list with total=0."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await paginate(query=query, page=1, per_page=25, session=session)

        assert result.items == []
        assert result.total == 0
        assert result.page == 1
        assert result.per_page == 25

    @pytest.mark.asyncio
    async def test_session_execute_called_twice(self) -> None:
        """paginate() should call session.execute exactly twice: count + data."""
        from app.services.pagination_service import paginate

        session = AsyncMock()
        query = _make_mock_query()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 10

        data_result = MagicMock()
        data_result.scalars.return_value = data_result
        data_result.all.return_value = [{"id": 1}]

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        await paginate(query=query, page=1, per_page=10, session=session)

        assert session.execute.await_count == 2
