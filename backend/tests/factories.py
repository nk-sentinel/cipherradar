"""Factory Boy test data factories for all core models.

All factories produce ``dict`` instances (not ORM objects) so they can be
used seamlessly with ``MagicMock`` and ``AsyncMock`` without requiring a
live database.

Usage::

    from tests.factories import UserFactory, ProjectFactory

    user = UserFactory()                 # dict with sensible defaults
    user = UserFactory(role="org_admin") # override any field
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import factory


# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------


class OrgFactory(factory.Factory):
    """Produce organisation dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    name = factory.Sequence(lambda n: f"org-{n}")
    plan = "free"
    settings = None
    description = None
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class UserFactory(factory.Factory):
    """Produce user dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    email = factory.Sequence(lambda n: f"user{n}@test.com")
    hashed_password = "$2b$12$fakehashfakehashfakehashfakehashfakehashfakehashfake"
    role = "developer"
    is_active = True
    auth_source = "local"
    org_id = factory.LazyFunction(uuid.uuid4)
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


class GroupFactory(factory.Factory):
    """Produce group dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    name = factory.Sequence(lambda n: f"group-{n}")
    org_id = factory.LazyFunction(uuid.uuid4)
    parent_group_id = None
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------


class ProjectFactory(factory.Factory):
    """Produce project dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    name = factory.Sequence(lambda n: f"project-{n}")
    type = "repository"
    org_id = factory.LazyFunction(uuid.uuid4)
    group_id = factory.LazyFunction(uuid.uuid4)
    git_url = None
    provider = None
    settings = None
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class ScanFactory(factory.Factory):
    """Produce scan dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    project_id = factory.LazyFunction(uuid.uuid4)
    org_id = factory.LazyFunction(uuid.uuid4)
    status = "queued"
    branch = "main"
    commit_sha = factory.LazyFunction(lambda: uuid.uuid4().hex[:40])
    findings_count = 0
    started_at = None
    completed_at = None
    error_message = None
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class FindingFactory(factory.Factory):
    """Produce finding dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    scan_id = factory.LazyFunction(uuid.uuid4)
    project_id = factory.LazyFunction(uuid.uuid4)
    org_id = factory.LazyFunction(uuid.uuid4)
    rule_id = factory.Sequence(lambda n: f"cbom-python-{n}")
    name = factory.Sequence(lambda n: f"AES-{128 + n}")
    severity = "high"
    confidence = "high"
    quantum_status = "vulnerable"
    asset_type = "algorithm"
    location_file = factory.Sequence(lambda n: f"src/crypto_{n}.py")
    location_line = factory.Sequence(lambda n: n + 1)
    properties = None
    status = "open"
    fingerprint = factory.LazyFunction(lambda: uuid.uuid4().hex[:64])
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLogFactory(factory.Factory):
    """Produce audit log entry dicts."""

    class Meta:
        model = dict

    id = factory.LazyFunction(uuid.uuid4)
    org_id = factory.LazyFunction(uuid.uuid4)
    user_id = factory.LazyFunction(uuid.uuid4)
    action_type = "user.login"
    resource_type = "user"
    resource_id = None
    details = None
    ip_address = None
    user_agent = None
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
