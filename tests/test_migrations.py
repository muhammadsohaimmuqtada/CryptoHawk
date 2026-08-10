from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from cryptohawk.storage import audit as audit_storage  # noqa: F401
from cryptohawk.storage import auth as auth_storage  # noqa: F401
from cryptohawk.storage import inventory as inventory_storage  # noqa: F401
from cryptohawk.storage import queue as queue_storage  # noqa: F401
from cryptohawk.storage.database import Base


def _config(database_url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _index_names(inspector, table_name: str) -> set[str]:
    return {
        index["name"]
        for index in inspector.get_indexes(table_name)
        if index.get("name") is not None
    }


def _unique_constraint_names(inspector, table_name: str) -> set[str]:
    return {
        constraint["name"]
        for constraint in inspector.get_unique_constraints(table_name)
        if constraint.get("name") is not None
    }


def test_initial_migration_matches_orm_and_round_trips(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.db'}"
    config = _config(database_url)

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    expected_tables = set(Base.metadata.tables)
    actual_tables = set(inspector.get_table_names()) - {"alembic_version"}
    assert actual_tables == expected_tables

    for table_name, table in Base.metadata.tables.items():
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        expected_columns = {column.name for column in table.columns}
        assert actual_columns == expected_columns, table_name

        expected_indexes = {index.name for index in table.indexes if index.name is not None}
        assert _index_names(inspector, table_name) == expected_indexes, table_name

        expected_uniques = {
            constraint.name
            for constraint in table.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
            and constraint.name is not None
        }
        assert _unique_constraint_names(inspector, table_name) == expected_uniques, table_name

    command.downgrade(config, "base")
    inspector = inspect(engine)
    assert not (set(inspector.get_table_names()) & expected_tables)

    command.upgrade(config, "head")
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) - {"alembic_version"} == expected_tables
