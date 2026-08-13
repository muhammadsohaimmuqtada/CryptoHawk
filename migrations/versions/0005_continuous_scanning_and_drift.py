"""Add scheduled scanning, evidence history, and drift tracking.

Revision ID: 0005_continuous_scanning_and_drift
Revises: 0004_connector_credentials
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_continuous_scanning_and_drift"
down_revision: str | None = "0004_connector_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["managed_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "asset_id",
            name="uq_scan_schedule_workspace_asset",
        ),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "enabled",
        "next_run_at",
        "created_by",
        "created_at",
        "updated_at",
    ):
        op.create_index(f"ix_scan_schedules_{column}", "scan_schedules", [column])

    op.create_table(
        "scheduled_executions",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("schedule_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["schedule_id"], ["scan_schedules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("job_id"),
        sa.UniqueConstraint(
            "schedule_id",
            "scheduled_for",
            name="uq_scheduled_execution_occurrence",
        ),
    )
    for column in (
        "schedule_id",
        "workspace_id",
        "asset_id",
        "scheduled_for",
        "enqueued_at",
    ):
        op.create_index(
            f"ix_scheduled_executions_{column}",
            "scheduled_executions",
            [column],
        )

    op.create_table(
        "scan_snapshots",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("origin", sa.String(length=30), nullable=False),
        sa.Column("schedule_id", sa.String(length=64), nullable=True),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("scanner_version", sa.String(length=80), nullable=False),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.Column("fingerprint_set_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("job_id"),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "origin",
        "schedule_id",
        "scheduled_for",
        "completed_at",
        "fingerprint_set_hash",
    ):
        op.create_index(f"ix_scan_snapshots_{column}", "scan_snapshots", [column])

    op.create_table(
        "observation_states",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_job_id", sa.String(length=64), nullable=False),
        sa.Column("last_job_id", sa.String(length=64), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("quantum_status", sa.String(length=30), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("finding_payload", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "asset_id",
            "fingerprint",
            name="uq_observation_state_identity",
        ),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "fingerprint",
        "active",
        "first_seen",
        "last_seen",
        "first_job_id",
        "last_job_id",
        "risk_score",
        "severity",
        "quantum_status",
        "updated_at",
    ):
        op.create_index(
            f"ix_observation_states_{column}",
            "observation_states",
            [column],
        )

    op.create_table(
        "observation_occurrences",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("quantum_status", sa.String(length=30), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("finding_payload", sa.Text(), nullable=False),
        sa.Column("scanner_version", sa.String(length=80), nullable=False),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "job_id",
            "fingerprint",
            name="uq_observation_occurrence_job_fingerprint",
        ),
    )
    for column in (
        "job_id",
        "workspace_id",
        "asset_id",
        "fingerprint",
        "finding_id",
        "observed_at",
        "risk_score",
        "severity",
        "quantum_status",
    ):
        op.create_index(
            f"ix_observation_occurrences_{column}",
            "observation_occurrences",
            [column],
        )

    op.create_table(
        "drift_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("scan_job_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("previous_risk_score", sa.Integer(), nullable=True),
        sa.Column("new_risk_score", sa.Integer(), nullable=True),
        sa.Column("previous_severity", sa.String(length=20), nullable=True),
        sa.Column("new_severity", sa.String(length=20), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "workspace_id",
        "asset_id",
        "scan_job_id",
        "fingerprint",
        "event_type",
        "occurred_at",
    ):
        op.create_index(f"ix_drift_events_{column}", "drift_events", [column])


def downgrade() -> None:
    for column in (
        "occurred_at",
        "event_type",
        "fingerprint",
        "scan_job_id",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(f"ix_drift_events_{column}", table_name="drift_events")
    op.drop_table("drift_events")

    for column in (
        "quantum_status",
        "severity",
        "risk_score",
        "observed_at",
        "finding_id",
        "fingerprint",
        "asset_id",
        "workspace_id",
        "job_id",
    ):
        op.drop_index(
            f"ix_observation_occurrences_{column}",
            table_name="observation_occurrences",
        )
    op.drop_table("observation_occurrences")

    for column in (
        "updated_at",
        "quantum_status",
        "severity",
        "risk_score",
        "last_job_id",
        "first_job_id",
        "last_seen",
        "first_seen",
        "active",
        "fingerprint",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(
            f"ix_observation_states_{column}",
            table_name="observation_states",
        )
    op.drop_table("observation_states")

    for column in (
        "fingerprint_set_hash",
        "completed_at",
        "scheduled_for",
        "schedule_id",
        "origin",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(f"ix_scan_snapshots_{column}", table_name="scan_snapshots")
    op.drop_table("scan_snapshots")

    for column in (
        "enqueued_at",
        "scheduled_for",
        "asset_id",
        "workspace_id",
        "schedule_id",
    ):
        op.drop_index(
            f"ix_scheduled_executions_{column}",
            table_name="scheduled_executions",
        )
    op.drop_table("scheduled_executions")

    for column in (
        "updated_at",
        "created_at",
        "created_by",
        "next_run_at",
        "enabled",
        "asset_id",
        "workspace_id",
    ):
        op.drop_index(f"ix_scan_schedules_{column}", table_name="scan_schedules")
    op.drop_table("scan_schedules")
