"""Add workspace retention policies.

Revision ID: 0009_workspace_retention_policies
Revises: 0008_crypto_policy_packs
Create Date: 2026-08-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_workspace_retention_policies"
down_revision: str | None = "0008_crypto_policy_packs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workspace_retention_policies",
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_retention_days", sa.Integer(), nullable=False),
        sa.Column("audit_retention_days", sa.Integer(), nullable=False),
        sa.Column("sweep_interval_hours", sa.Integer(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "evidence_retention_days >= 7 AND evidence_retention_days <= 3650",
            name="ck_retention_evidence_days",
        ),
        sa.CheckConstraint(
            "audit_retention_days >= 7 AND audit_retention_days <= 3650",
            name="ck_retention_audit_days",
        ),
        sa.CheckConstraint(
            "sweep_interval_hours >= 1 AND sweep_interval_hours <= 168",
            name="ck_retention_sweep_hours",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("workspace_id"),
    )
    op.create_index(
        "ix_workspace_retention_policies_enabled",
        "workspace_retention_policies",
        ["enabled"],
    )
    op.create_index(
        "ix_workspace_retention_policies_last_run_at",
        "workspace_retention_policies",
        ["last_run_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_workspace_retention_policies_last_run_at",
        table_name="workspace_retention_policies",
    )
    op.drop_index(
        "ix_workspace_retention_policies_enabled",
        table_name="workspace_retention_policies",
    )
    op.drop_table("workspace_retention_policies")
