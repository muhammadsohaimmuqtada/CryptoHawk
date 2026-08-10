"""Create the initial CryptoHawk schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=255), nullable=False),
        sa.Column("asset_name", sa.String(length=500), nullable=False),
        sa.Column("family", sa.String(length=100), nullable=False),
        sa.Column("algorithm", sa.String(length=255), nullable=False),
        sa.Column("primitive", sa.String(length=50), nullable=False),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("quantum_status", sa.String(length=30), nullable=False),
        sa.Column("migration_target", sa.String(length=100), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_discovered_at", "findings", ["discovered_at"])
    op.create_index("ix_findings_family", "findings", ["family"])
    op.create_index("ix_findings_quantum_status", "findings", ["quantum_status"])
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "finding_scopes",
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("managed_asset_id", sa.String(length=64), nullable=False),
        sa.Column("scan_job_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id"),
    )
    op.create_index(
        "ix_finding_scopes_managed_asset_id",
        "finding_scopes",
        ["managed_asset_id"],
    )
    op.create_index("ix_finding_scopes_scan_job_id", "finding_scopes", ["scan_job_id"])
    op.create_index("ix_finding_scopes_workspace_id", "finding_scopes", ["workspace_id"])

    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_workspaces_created_at", "workspaces", ["created_at"])
    op.create_index("ix_workspaces_slug", "workspaces", ["slug"], unique=True)

    op.create_table(
        "managed_assets",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("locator", sa.String(length=1000), nullable=False),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False),
        sa.Column("asset_criticality", sa.Integer(), nullable=False),
        sa.Column("data_lifetime_years", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(length=80), nullable=False),
        sa.Column("tags_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "kind",
            "locator",
            name="uq_managed_asset_workspace_kind_locator",
        ),
    )
    op.create_index("ix_managed_assets_created_at", "managed_assets", ["created_at"])
    op.create_index("ix_managed_assets_kind", "managed_assets", ["kind"])
    op.create_index("ix_managed_assets_updated_at", "managed_assets", ["updated_at"])
    op.create_index("ix_managed_assets_workspace_id", "managed_assets", ["workspace_id"])

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_active", "users", ["active"])
    op.create_index("ix_users_created_at", "users", ["created_at"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["managed_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_jobs_asset_id", "scan_jobs", ["asset_id"])
    op.create_index("ix_scan_jobs_kind", "scan_jobs", ["kind"])
    op.create_index("ix_scan_jobs_requested_at", "scan_jobs", ["requested_at"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_workspace_id", "scan_jobs", ["workspace_id"])

    op.create_table(
        "workspace_memberships",
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("workspace_id", "user_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "user_id",
            name="uq_membership_workspace_user",
        ),
    )
    op.create_index(
        "ix_workspace_memberships_created_at",
        "workspace_memberships",
        ["created_at"],
    )
    op.create_index("ix_workspace_memberships_role", "workspace_memberships", ["role"])

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_sessions_created_at", "auth_sessions", ["created_at"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions", ["token_hash"], unique=True)
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("prefix", sa.String(length=24), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"])
    op.create_index("ix_api_keys_role", "api_keys", ["role"])
    op.create_index("ix_api_keys_token_hash", "api_keys", ["token_hash"], unique=True)
    op.create_index("ix_api_keys_workspace_id", "api_keys", ["workspace_id"])

    op.create_table(
        "scan_queue",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("job_id"),
    )
    op.create_index("ix_scan_queue_cancel_requested", "scan_queue", ["cancel_requested"])
    op.create_index("ix_scan_queue_lease_expires_at", "scan_queue", ["lease_expires_at"])
    op.create_index("ix_scan_queue_lease_owner", "scan_queue", ["lease_owner"])
    op.create_index("ix_scan_queue_next_attempt_at", "scan_queue", ["next_attempt_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("actor_kind", sa.String(length=40), nullable=False),
        sa.Column("actor_id", sa.String(length=200), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=200), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=1000), nullable=True),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_actor_kind", "audit_events", ["actor_kind"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_index("ix_audit_events_outcome", "audit_events", ["outcome"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    op.create_index("ix_audit_events_resource_type", "audit_events", ["resource_type"])
    op.create_index("ix_audit_events_user_id", "audit_events", ["user_id"])
    op.create_index("ix_audit_events_workspace_id", "audit_events", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_workspace_id", table_name="audit_events")
    op.drop_index("ix_audit_events_user_id", table_name="audit_events")
    op.drop_index("ix_audit_events_resource_type", table_name="audit_events")
    op.drop_index("ix_audit_events_request_id", table_name="audit_events")
    op.drop_index("ix_audit_events_outcome", table_name="audit_events")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_kind", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_id", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_scan_queue_next_attempt_at", table_name="scan_queue")
    op.drop_index("ix_scan_queue_lease_owner", table_name="scan_queue")
    op.drop_index("ix_scan_queue_lease_expires_at", table_name="scan_queue")
    op.drop_index("ix_scan_queue_cancel_requested", table_name="scan_queue")
    op.drop_table("scan_queue")

    op.drop_index("ix_api_keys_workspace_id", table_name="api_keys")
    op.drop_index("ix_api_keys_token_hash", table_name="api_keys")
    op.drop_index("ix_api_keys_role", table_name="api_keys")
    op.drop_index("ix_api_keys_prefix", table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_token_hash", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_expires_at", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_created_at", table_name="auth_sessions")
    op.drop_table("auth_sessions")

    op.drop_index("ix_workspace_memberships_role", table_name="workspace_memberships")
    op.drop_index(
        "ix_workspace_memberships_created_at",
        table_name="workspace_memberships",
    )
    op.drop_table("workspace_memberships")

    op.drop_index("ix_scan_jobs_workspace_id", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_requested_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_kind", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_asset_id", table_name="scan_jobs")
    op.drop_table("scan_jobs")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_created_at", table_name="users")
    op.drop_index("ix_users_active", table_name="users")
    op.drop_table("users")

    op.drop_index("ix_managed_assets_workspace_id", table_name="managed_assets")
    op.drop_index("ix_managed_assets_updated_at", table_name="managed_assets")
    op.drop_index("ix_managed_assets_kind", table_name="managed_assets")
    op.drop_index("ix_managed_assets_created_at", table_name="managed_assets")
    op.drop_table("managed_assets")

    op.drop_index("ix_workspaces_slug", table_name="workspaces")
    op.drop_index("ix_workspaces_created_at", table_name="workspaces")
    op.drop_table("workspaces")

    op.drop_index("ix_finding_scopes_workspace_id", table_name="finding_scopes")
    op.drop_index("ix_finding_scopes_scan_job_id", table_name="finding_scopes")
    op.drop_index("ix_finding_scopes_managed_asset_id", table_name="finding_scopes")
    op.drop_table("finding_scopes")

    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_risk_score", table_name="findings")
    op.drop_index("ix_findings_quantum_status", table_name="findings")
    op.drop_index("ix_findings_family", table_name="findings")
    op.drop_index("ix_findings_discovered_at", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_table("findings")
