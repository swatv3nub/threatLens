"""Add tenant scope columns to existing deployments."""

import sqlalchemy as sa

from alembic import op

revision = "0002_tenant_scope"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

TABLES = (
    "alerts",
    "triage_results",
    "evidence",
    "tool_calls",
    "agent_runs",
    "audit_events",
)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for table in TABLES:
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "tenant_id" not in columns:
            op.add_column(table, sa.Column("tenant_id", sa.String(length=128), nullable=True))
        indexes = {index["name"] for index in inspector.get_indexes(table)}
        index_name = f"ix_{table}_tenant_id"
        if index_name not in indexes:
            op.create_index(index_name, table, ["tenant_id"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for table in reversed(TABLES):
        indexes = {index["name"] for index in inspector.get_indexes(table)}
        index_name = f"ix_{table}_tenant_id"
        if index_name in indexes:
            op.drop_index(index_name, table_name=table)
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "tenant_id" in columns:
            op.drop_column(table, "tenant_id")
