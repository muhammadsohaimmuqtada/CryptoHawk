"""Add migration remediation queue.

Revision ID: 0007_migration_remediation_queue
Revises: 0006_repository_native_collector
Create Date: 2026-08-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_migration_remediation_queue"
down_revision: str | None = "0006_repository_native_collector"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "migration_items",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("observation_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source_finding_id", sa.String(length=64), nullable=False),
        sa.Column("source_scan_job_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("priority", sa.String(length=20), nullable=False),
        sa.Column("target_algorithm", sa.String(length=200), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("acceptance_reason", sa.Text(), nullable=True),
        sa.Column("verification_job_id", sa.String(length=64), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_evidence_json", sa.Text(), nullable=False),
        sa.Column("source_finding_json", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["managed_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_scan_job_id"], ["scan_jobs.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["verification_job_id"], ["scan_jobs.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "asset_id",
            "observation_fingerprint",
            name="uq_migration_item_workspace_asset_fingerprint",
        ),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "observation_fingerprint",
        "source_finding_id",
        "source_scan_job_id",
        "owner",
        "status",
        "priority",
        "due_date",
        "verification_job_id",
        "created_by",
        "created_at",
        "updated_at",
    ):
        op.create_index(f"ix_migration_items_{column}", "migration_items", [column])


def downgrade() -> None:
    for column in (
        "updated_at",
        "created_at",
        "created_by",
        "verification_job_id",
        "due_date",
        "priority",
        "status",
        "owner",
        "source_scan_job_id",
        "source_finding_id",
        "observation_fingerprint",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(f"ix_migration_items_{column}", table_name="migration_items")
    op.drop_table("migration_items")
