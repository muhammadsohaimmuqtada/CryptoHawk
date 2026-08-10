"""Add API-key creation-time index.

Revision ID: 0002_api_key_created_at_index
Revises: 0001_initial_schema
Create Date: 2026-08-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_api_key_created_at_index"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_api_keys_created_at", "api_keys", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_created_at", table_name="api_keys")
