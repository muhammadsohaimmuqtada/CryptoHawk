from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Column, MetaData, String, Table, engine_from_config, inspect, pool
from sqlalchemy.engine import Connection

from cryptohawk.storage import audit as audit_storage  # noqa: F401
from cryptohawk.storage import auth as auth_storage  # noqa: F401
from cryptohawk.storage import continuous as continuous_storage  # noqa: F401
from cryptohawk.storage import credentials as credential_storage  # noqa: F401
from cryptohawk.storage import inventory as inventory_storage  # noqa: F401
from cryptohawk.storage import queue as queue_storage  # noqa: F401
from cryptohawk.storage import quotas as quota_storage  # noqa: F401
from cryptohawk.storage.database import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

runtime_url = os.getenv("CRYPTOHAWK_DATABASE_URL")
if runtime_url:
    config.set_main_option("sqlalchemy.url", runtime_url)

target_metadata = Base.metadata
_VERSION_TABLE = "alembic_version"
_VERSION_COLUMN_LENGTH = 128


def _ensure_version_table_capacity(connection: Connection) -> None:
    """Keep historical human-readable revision IDs portable to strict databases.

    Alembic's built-in version table uses VARCHAR(32). CryptoHawk already shipped
    revision IDs longer than 32 characters, which SQLite accepts but PostgreSQL
    correctly rejects. Pre-creating a wider version table preserves those existing
    revision identities without renaming migration history. Existing PostgreSQL
    installations at an earlier short revision are widened before the next stamp.
    """

    inspector = inspect(connection)
    if not inspector.has_table(_VERSION_TABLE):
        metadata = MetaData()
        Table(
            _VERSION_TABLE,
            metadata,
            Column(
                "version_num",
                String(_VERSION_COLUMN_LENGTH),
                nullable=False,
                primary_key=True,
            ),
        ).create(connection)
        return

    columns = inspector.get_columns(_VERSION_TABLE)
    version_column = next(
        (column for column in columns if column.get("name") == "version_num"),
        None,
    )
    if version_column is None:
        raise RuntimeError("alembic_version table is missing version_num")

    current_length = getattr(version_column.get("type"), "length", None)
    if current_length is None or current_length >= _VERSION_COLUMN_LENGTH:
        return

    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "ALTER TABLE alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(128)"
        )
        return

    if connection.dialect.name == "sqlite":
        # SQLite does not enforce declared VARCHAR lengths. Existing SQLite
        # databases may retain VARCHAR(32) while safely storing the shipped IDs.
        return

    raise RuntimeError(
        "alembic_version.version_num is too narrow for CryptoHawk revision IDs"
    )


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _ensure_version_table_capacity(connection)
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
