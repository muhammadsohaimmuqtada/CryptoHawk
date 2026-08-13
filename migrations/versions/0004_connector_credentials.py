"""Add encrypted connector credential storage.

Revision ID: 0004_connector_credentials
Revises: 0003_request_quotas_and_scan_capacity
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_connector_credentials"
down_revision: str | None = "0003_request_quotas_and_scan_capacity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "connector_credentials",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=50), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("secret_fields_json", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id",
            "name",
            name="uq_connector_credentials_workspace_name",
        ),
    )
    op.create_index(
        "ix_connector_credentials_workspace_id",
        "connector_credentials",
        ["workspace_id"],
    )
    op.create_index(
        "ix_connector_credentials_kind",
        "connector_credentials",
        ["kind"],
    )
    op.create_index(
        "ix_connector_credentials_key_version",
        "connector_credentials",
        ["key_version"],
    )
    op.create_index(
        "ix_connector_credentials_created_by",
        "connector_credentials",
        ["created_by"],
    )
    op.create_index(
        "ix_connector_credentials_created_at",
        "connector_credentials",
        ["created_at"],
    )
    op.create_index(
        "ix_connector_credentials_updated_at",
        "connector_credentials",
        ["updated_at"],
    )
    op.create_index(
        "ix_connector_credentials_last_used_at",
        "connector_credentials",
        ["last_used_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_connector_credentials_last_used_at",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_updated_at",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_created_at",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_created_by",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_key_version",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_kind",
        table_name="connector_credentials",
    )
    op.drop_index(
        "ix_connector_credentials_workspace_id",
        table_name="connector_credentials",
    )
    op.drop_table("connector_credentials")
