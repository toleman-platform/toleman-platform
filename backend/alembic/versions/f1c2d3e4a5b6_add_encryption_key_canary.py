"""add encryption key canary

Single-row marker table letting app.core.crypto detect a
PLATFORM_ENCRYPTION_KEY mismatch proactively at startup rather than as a
buried decrypt traceback the first time a feature touches an encrypted
secret. See EncryptionKeyCanary's docstring in app/models/models.py.

Revision ID: f1c2d3e4a5b6
Revises: ac9daa1d9a66
Create Date: 2026-08-20

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f1c2d3e4a5b6"
down_revision: Union[str, None] = "ac9daa1d9a66"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "encryptionkeycanary",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("encryptionkeycanary")
