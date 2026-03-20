"""Enable Row Level Security and create tenant isolation policies.

Adds RLS policies on all tenant-scoped tables so that queries are
automatically filtered to the organisation identified by the
``app.current_org_id`` session variable (set via ``SET LOCAL`` in
``app.db.rls.set_tenant_context``).

Tables covered: projects, scans, findings, cbom_documents, scan_metrics.

Note: RLS only takes effect for non-superuser roles.  The application
database user must NOT be a superuser in production.

Revision ID: 003_rls_policies
Revises: 002_add_org_id
Create Date: 2026-03-20
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003_rls_policies"
down_revision: str | None = "002_add_org_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tables that carry an ``org_id`` column and need tenant isolation.
_TENANT_TABLES = [
    "projects",
    "scans",
    "findings",
    "cbom_documents",
]


def upgrade() -> None:
    # Enable RLS and create tenant isolation policies for org_id tables.
    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            f"USING (org_id = current_setting('app.current_org_id')::uuid)"
        )

    # scan_metrics does not have org_id but has project_id.
    # Enforce RLS via a subquery that joins through projects.
    op.execute("ALTER TABLE scan_metrics ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation_scan_metrics ON scan_metrics "
        "USING (project_id IN ("
        "  SELECT id FROM projects "
        "  WHERE org_id = current_setting('app.current_org_id')::uuid"
        "))"
    )

    # Groups table: also tenant-scoped.
    op.execute("ALTER TABLE groups ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation_groups ON groups USING (org_id = current_setting('app.current_org_id')::uuid)"
    )


def downgrade() -> None:
    # Drop policies and disable RLS in reverse order.
    op.execute("DROP POLICY IF EXISTS tenant_isolation_groups ON groups")
    op.execute("ALTER TABLE groups DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS tenant_isolation_scan_metrics ON scan_metrics")
    op.execute("ALTER TABLE scan_metrics DISABLE ROW LEVEL SECURITY")

    for table in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
