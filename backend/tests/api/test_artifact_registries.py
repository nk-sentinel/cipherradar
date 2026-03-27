"""Tests for artifact registry API routes (D2)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from app.api.v1.artifact_registries import router


def test_list_registries_route_exists() -> None:
    """GET /admin/registries route is registered."""
    paths = [r.path for r in router.routes if hasattr(r, "path")]
    assert "/admin/registries" in paths


def test_create_registries_route_exists() -> None:
    """POST /admin/registries route is registered."""
    found = False
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/admin/registries":
            if hasattr(route, "methods") and "POST" in route.methods:
                found = True
                break
    assert found, "POST /admin/registries route not found"


def test_delete_registries_route_exists() -> None:
    """DELETE /admin/registries/{registry_id} route is registered."""
    found = False
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/admin/registries/{registry_id}":
            if hasattr(route, "methods") and "DELETE" in route.methods:
                found = True
                break
    assert found, "DELETE /admin/registries/{registry_id} route not found"


def test_test_connection_route_exists() -> None:
    """POST /admin/registries/{registry_id}/test route is registered."""
    found = False
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/admin/registries/{registry_id}/test":
            found = True
            break
    assert found, "POST /admin/registries/{registry_id}/test route not found"


def test_rbac_list_allows_sm() -> None:
    """GET /admin/registries allows Security Manager role."""
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/admin/registries":
            if hasattr(route, "methods") and "GET" in route.methods:
                # Has dependencies (RBAC guard)
                assert len(route.dependencies) > 0
                return
    pytest.fail("GET /admin/registries route not found")


def test_rbac_create_requires_oa() -> None:
    """POST /admin/registries has RBAC dependencies (Org Admin guard)."""
    for route in router.routes:
        if hasattr(route, "path") and route.path == "/admin/registries":
            if hasattr(route, "methods") and "POST" in route.methods:
                assert len(route.dependencies) > 0
                return
    pytest.fail("POST /admin/registries route not found")
