"""Add the ordered investigation ledger."""

import sqlalchemy as sa

from alembic import op

revision = "0003_investigation_ledger"
down_revision = "0002_tenant_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "investigation_ledger" in inspector.get_table_names():
        return
    op.create_table(
        "investigation_ledger",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("triage_id", sa.String(length=64), nullable=True),
        sa.Column("agent_run_id", sa.String(length=64), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("step_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("tenant_id", "alert_id", "triage_id", "agent_run_id", "sequence", "step_type"):
        op.create_index(f"ix_investigation_ledger_{column}", "investigation_ledger", [column])


def downgrade() -> None:
    op.drop_table("investigation_ledger")
