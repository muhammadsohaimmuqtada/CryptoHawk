"""Add shared request quotas and workspace scan capacity.

Revision ID: 0003_request_quotas_and_scan_capacity
Revises: 0002_api_key_created_at_index
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_request_quotas_and_scan_capacity"
down_revision: str | None = "0002_api_key_created_at_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_buckets",
        sa.Column("scope_key", sa.String(length=300), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("window_start", sa.BigInteger(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("scope_key", "action", "window_start"),
    )
    op.create_index(
        "ix_rate_limit_buckets_updated_at",
        "rate_limit_buckets",
        ["updated_at"],
    )

    op.create_table(
        "workspace_runtime",
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("active_scans", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("workspace_id"),
    )
    op.create_index(
        "ix_workspace_runtime_updated_at",
        "workspace_runtime",
        ["updated_at"],
    )
    op.execute(
        sa.text(
            "INSERT INTO workspace_runtime (workspace_id, active_scans, updated_at) "
            "SELECT id, 0, CURRENT_TIMESTAMP FROM workspaces"
        )
    )


def downgrade() -> None:
    op.drop_index("ix_workspace_runtime_updated_at", table_name="workspace_runtime")
    op.drop_table("workspace_runtime")
    op.drop_index("ix_rate_limit_buckets_updated_at", table_name="rate_limit_buckets")
    op.drop_table("rate_limit_buckets")
