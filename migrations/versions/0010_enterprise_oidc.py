"""Add enterprise OIDC identity and one-time login state.

Revision ID: 0010_enterprise_oidc
Revises: 0009_workspace_retention_policies
Create Date: 2026-08-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_enterprise_oidc"
down_revision: str | None = "0009_workspace_retention_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_identities",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=1000), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("email_at_link", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_identity_issuer_subject"),
        sa.UniqueConstraint("issuer", "user_id", name="uq_oidc_identity_issuer_user"),
    )
    op.create_index("ix_oidc_identities_issuer", "oidc_identities", ["issuer"])
    op.create_index("ix_oidc_identities_subject", "oidc_identities", ["subject"])
    op.create_index("ix_oidc_identities_user_id", "oidc_identities", ["user_id"])
    op.create_index("ix_oidc_identities_created_at", "oidc_identities", ["created_at"])
    op.create_index("ix_oidc_identities_last_login_at", "oidc_identities", ["last_login_at"])

    op.create_table(
        "oidc_login_transactions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("browser_binding_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("payload_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_oidc_login_transactions_state_hash",
        "oidc_login_transactions",
        ["state_hash"],
        unique=True,
    )
    op.create_index(
        "ix_oidc_login_transactions_browser_binding_hash",
        "oidc_login_transactions",
        ["browser_binding_hash"],
    )
    op.create_index(
        "ix_oidc_login_transactions_created_at",
        "oidc_login_transactions",
        ["created_at"],
    )
    op.create_index(
        "ix_oidc_login_transactions_expires_at",
        "oidc_login_transactions",
        ["expires_at"],
    )

    op.create_table(
        "oidc_login_completions",
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("browser_binding_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("code_hash"),
    )
    op.create_index(
        "ix_oidc_login_completions_browser_binding_hash",
        "oidc_login_completions",
        ["browser_binding_hash"],
    )
    op.create_index(
        "ix_oidc_login_completions_user_id",
        "oidc_login_completions",
        ["user_id"],
    )
    op.create_index(
        "ix_oidc_login_completions_created_at",
        "oidc_login_completions",
        ["created_at"],
    )
    op.create_index(
        "ix_oidc_login_completions_expires_at",
        "oidc_login_completions",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_oidc_login_completions_expires_at",
        table_name="oidc_login_completions",
    )
    op.drop_index(
        "ix_oidc_login_completions_created_at",
        table_name="oidc_login_completions",
    )
    op.drop_index(
        "ix_oidc_login_completions_user_id",
        table_name="oidc_login_completions",
    )
    op.drop_index(
        "ix_oidc_login_completions_browser_binding_hash",
        table_name="oidc_login_completions",
    )
    op.drop_table("oidc_login_completions")

    op.drop_index(
        "ix_oidc_login_transactions_expires_at",
        table_name="oidc_login_transactions",
    )
    op.drop_index(
        "ix_oidc_login_transactions_created_at",
        table_name="oidc_login_transactions",
    )
    op.drop_index(
        "ix_oidc_login_transactions_browser_binding_hash",
        table_name="oidc_login_transactions",
    )
    op.drop_index(
        "ix_oidc_login_transactions_state_hash",
        table_name="oidc_login_transactions",
    )
    op.drop_table("oidc_login_transactions")

    op.drop_index("ix_oidc_identities_last_login_at", table_name="oidc_identities")
    op.drop_index("ix_oidc_identities_created_at", table_name="oidc_identities")
    op.drop_index("ix_oidc_identities_user_id", table_name="oidc_identities")
    op.drop_index("ix_oidc_identities_subject", table_name="oidc_identities")
    op.drop_index("ix_oidc_identities_issuer", table_name="oidc_identities")
    op.drop_table("oidc_identities")
