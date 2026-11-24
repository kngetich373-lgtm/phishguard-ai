"""Migrate legacy API keys to hashed storage without invalidating them.

Revision ID: 72ac0c9d41e2
Revises: 15cc4a64521b
"""
import hashlib
from typing import Sequence, Union

from alembic import op
from alembic import context
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "72ac0c9d41e2"
down_revision: Union[str, None] = "15cc4a64521b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    inspector = inspect(bind)
    if "api_keys" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("api_keys")}
    if "key_hash" not in columns:
        op.add_column("api_keys", sa.Column("key_hash", sa.String(), nullable=True))
    if "key_prefix" not in columns:
        op.add_column("api_keys", sa.Column("key_prefix", sa.String(), nullable=True))

    rows = bind.execute(
        sa.text("SELECT id, key, key_hash FROM api_keys WHERE key_hash IS NULL")
    ).mappings()
    for row in rows:
        raw_key = row["key"]
        hashed_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        bind.execute(
            sa.text(
                "UPDATE api_keys SET key = :key_hash, key_hash = :key_hash, "
                "key_prefix = :key_prefix WHERE id = :id"
            ),
            {
                "id": row["id"],
                "key_hash": hashed_key,
                "key_prefix": raw_key[:12],
            },
        )

    indexes = {index["name"] for index in inspect(bind).get_indexes("api_keys")}
    if "ix_api_keys_key_hash" not in indexes:
        op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    if "ix_api_keys_key_prefix" not in indexes:
        op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"], unique=False)


def downgrade() -> None:
    raise RuntimeError(
        "API key hashes cannot be safely reversed. Restore a verified backup "
        "before any manual rollback."
    )
