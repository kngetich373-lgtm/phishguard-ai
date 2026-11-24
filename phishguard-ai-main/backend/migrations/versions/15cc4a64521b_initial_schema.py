"""Create the existing core schema without dropping pre-existing tables.

Revision ID: 15cc4a64521b
Revises:
"""
from typing import Sequence, Union

from alembic import op
from alembic import context
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision: str = "15cc4a64521b"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_offline_enums = set()


def _enum_type(name: str, values: tuple[str, ...]):
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        enum_type = postgresql.ENUM(*values, name=name, create_type=False)
        if context.is_offline_mode():
            if name not in _offline_enums:
                literals = ", ".join(f"'{value}'" for value in values)
                op.execute(f"CREATE TYPE {name} AS ENUM ({literals})")
                _offline_enums.add(name)
        else:
            enum_type.create(bind, checkfirst=True)
        return enum_type
    return sa.Enum(*values, name=name)


def upgrade() -> None:
    bind = op.get_bind()
    offline = context.is_offline_mode()
    tables = set() if offline else set(inspect(bind).get_table_names())

    if "teams" not in tables:
        op.create_table(
            "teams",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("hashed_password", sa.String(), nullable=False),
            sa.Column("full_name", sa.String(), nullable=False),
            sa.Column("is_admin", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("team_id", sa.String(), nullable=True),
            sa.ForeignKeyConstraint(["team_id"], ["teams.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if "api_keys" not in tables:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("key", sa.String(), nullable=False),
            sa.Column("key_hash", sa.String(), nullable=True),
            sa.Column("key_prefix", sa.String(), nullable=True),
            sa.Column("label", sa.String(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("owner_id", sa.String(), nullable=False),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if "scans" not in tables:
        op.create_table(
            "scans",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_type", _enum_type("scantype", ("URL", "SMS", "EMAIL")), nullable=False),
            sa.Column("input_value", sa.Text(), nullable=False),
            sa.Column("verdict", _enum_type("verdict", ("SAFE", "SUSPICIOUS", "MALICIOUS")), nullable=False),
            sa.Column("risk_score", sa.Float(), nullable=False),
            sa.Column("reasons_json", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("owner_id", sa.String(), nullable=True),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if "alerts" not in tables:
        op.create_table(
            "alerts",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("title", sa.String(), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("severity", _enum_type("verdict", ("SAFE", "SUSPICIOUS", "MALICIOUS")), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("read", sa.Boolean(), nullable=False),
            sa.Column("owner_id", sa.String(), nullable=True),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    index_names = {} if offline else {
        table: {index["name"] for index in inspect(bind).get_indexes(table)}
        for table in ("users", "api_keys")
        if table in inspect(bind).get_table_names()
    }
    if "ix_users_email" not in index_names.get("users", set()):
        op.create_index("ix_users_email", "users", ["email"], unique=True)
    if "ix_api_keys_key" not in index_names.get("api_keys", set()):
        op.create_index("ix_api_keys_key", "api_keys", ["key"], unique=True)
    if "ix_api_keys_key_hash" not in index_names.get("api_keys", set()):
        api_key_columns = (
            {"key_hash", "key_prefix"}
            if offline
            else {column["name"] for column in inspect(bind).get_columns("api_keys")}
        )
        if "key_hash" in api_key_columns:
            op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    if "ix_api_keys_key_prefix" not in index_names.get("api_keys", set()):
        if offline:
            api_key_columns = {"key_hash", "key_prefix"}
        else:
            api_key_columns = {column["name"] for column in inspect(bind).get_columns("api_keys")}
        if "key_prefix" in api_key_columns:
            op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"], unique=False)


def downgrade() -> None:
    raise RuntimeError(
        "The initial schema may have adopted existing tables. Downgrade is disabled "
        "to prevent deleting existing customer data; use a verified backup restore."
    )
