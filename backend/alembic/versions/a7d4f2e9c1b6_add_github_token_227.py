"""add per-workspace github token storage (issue #227)

New `githubtoken` table holding a user-supplied GitHub PAT per workspace,
encrypted at rest (Fernet, app.core.crypto) with an optional expiry. Replaces
the unsafe env-only GITHUB_TOKEN pickup: the token now lives in the DB,
scoped to one workspace, never echoed back, and lazily purged on read once
``expires_at`` passes.

Revision ID: a7d4f2e9c1b6
Revises: 8f2d3a1b4c5e
Create Date: 2026-08-20

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
import sqlmodel

revision: str = "a7d4f2e9c1b6"
down_revision: Union[str, None] = "8f2d3a1b4c5e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "githubtoken",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("token_ciphertext", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspace.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["user.id"]),
        sa.UniqueConstraint("workspace_id"),
    )
    op.create_index("ix_githubtoken_workspace_id", "githubtoken", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_githubtoken_workspace_id", table_name="githubtoken")
    op.drop_table("githubtoken")
