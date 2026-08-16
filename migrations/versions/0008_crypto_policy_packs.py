"""Add versioned cryptographic policy packs.

Revision ID: 0008_crypto_policy_packs
Revises: 0007_migration_remediation_queue
Create Date: 2026-08-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_crypto_policy_packs"
down_revision: str | None = "0007_migration_remediation_queue"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "crypto_policy_packs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("built_in", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "slug",
            name="uq_crypto_policy_pack_workspace_slug",
        ),
    )
    for column in ("workspace_id", "slug", "built_in", "created_by", "created_at"):
        op.create_index(f"ix_crypto_policy_packs_{column}", "crypto_policy_packs", [column])

    op.create_table(
        "crypto_policy_versions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rules_json", sa.Text(), nullable=False),
        sa.Column("rules_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["crypto_policy_packs.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "policy_id",
            "version",
            name="uq_crypto_policy_version_number",
        ),
    )
    for column in ("policy_id", "workspace_id", "rules_hash", "created_by", "created_at"):
        op.create_index(
            f"ix_crypto_policy_versions_{column}",
            "crypto_policy_versions",
            [column],
        )

    op.create_table(
        "workspace_policy_assignments",
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("policy_version_id", sa.String(length=64), nullable=False),
        sa.Column("assigned_by", sa.String(length=200), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["policy_version_id"],
            ["crypto_policy_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("workspace_id"),
    )
    op.create_index(
        "ix_workspace_policy_assignments_policy_version_id",
        "workspace_policy_assignments",
        ["policy_version_id"],
    )
    op.create_index(
        "ix_workspace_policy_assignments_assigned_at",
        "workspace_policy_assignments",
        ["assigned_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_workspace_policy_assignments_assigned_at",
        table_name="workspace_policy_assignments",
    )
    op.drop_index(
        "ix_workspace_policy_assignments_policy_version_id",
        table_name="workspace_policy_assignments",
    )
    op.drop_table("workspace_policy_assignments")

    for column in ("created_at", "created_by", "rules_hash", "workspace_id", "policy_id"):
        op.drop_index(
            f"ix_crypto_policy_versions_{column}",
            table_name="crypto_policy_versions",
        )
    op.drop_table("crypto_policy_versions")

    for column in ("created_at", "created_by", "built_in", "slug", "workspace_id"):
        op.drop_index(
            f"ix_crypto_policy_packs_{column}",
            table_name="crypto_policy_packs",
        )
    op.drop_table("crypto_policy_packs")
