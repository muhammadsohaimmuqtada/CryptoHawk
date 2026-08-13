"""Add repository-native collector configuration and commit provenance.

Revision ID: 0006_repository_native_collector
Revises: 0005_continuous_scanning_and_drift
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_repository_native_collector"
down_revision: str | None = "0005_continuous_scanning_and_drift"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "repository_configurations",
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("repository_url", sa.String(length=1000), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("ref", sa.String(length=200), nullable=False),
        sa.Column("credential_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["managed_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["connector_credentials.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id"),
    )
    for column in (
        "workspace_id",
        "repository_url",
        "provider",
        "credential_id",
        "created_at",
        "updated_at",
    ):
        op.create_index(
            f"ix_repository_configurations_{column}",
            "repository_configurations",
            [column],
        )

    op.create_table(
        "repository_scan_runs",
        sa.Column("scan_job_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("repository_url", sa.String(length=1000), nullable=False),
        sa.Column("ref", sa.String(length=200), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=False),
        sa.Column("previous_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("scan_mode", sa.String(length=30), nullable=False),
        sa.Column("changed_paths", sa.Integer(), nullable=False),
        sa.Column("scanned_files", sa.Integer(), nullable=False),
        sa.Column("retained_observations", sa.Integer(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_job_id"),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "commit_sha",
        "scan_mode",
        "collected_at",
    ):
        op.create_index(
            f"ix_repository_scan_runs_{column}",
            "repository_scan_runs",
            [column],
        )


def downgrade() -> None:
    for column in (
        "collected_at",
        "scan_mode",
        "commit_sha",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(
            f"ix_repository_scan_runs_{column}",
            table_name="repository_scan_runs",
        )
    op.drop_table("repository_scan_runs")

    for column in (
        "updated_at",
        "created_at",
        "credential_id",
        "provider",
        "repository_url",
        "workspace_id",
    ):
        op.drop_index(
            f"ix_repository_configurations_{column}",
            table_name="repository_configurations",
        )
    op.drop_table("repository_configurations")
