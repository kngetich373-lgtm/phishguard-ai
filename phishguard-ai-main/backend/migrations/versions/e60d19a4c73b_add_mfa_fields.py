"""Add optional MFA fields to user accounts.

Revision ID: e60d19a4c73b
Revises: 62aeddc5d3b4
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e60d19a4c73b"
down_revision: Union[str, None] = "62aeddc5d3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("users", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True))


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade would discard MFA configuration. Restore a verified backup "
        "or apply a reviewed forward migration instead."
    )
