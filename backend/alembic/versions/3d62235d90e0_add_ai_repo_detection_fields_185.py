"""add ai repo detection fields (issue #185)

Adds the AI/ML repo flag every AI-specific scanner in epic #192 gates on,
plus the signal list explaining why it fired and a human override that wins
over detection.

Existing rows default to is_ai_repo=False / signals="" / override=NULL --
i.e. "not an AI repo, nobody has decided otherwise". Detection recomputes on
the next scan, so this is a safe starting state rather than a guess: a repo
that is genuinely an AI repo flips to True the first time it's scanned, and
nothing acts on the flag until then.

Revision ID: 3d62235d90e0
Revises: 0df342949bde
Create Date: 2026-08-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "3d62235d90e0"
down_revision: Union[str, None] = "0df342949bde"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "target",
        sa.Column("is_ai_repo", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "target",
        sa.Column("is_ai_repo_signals", sa.String(), nullable=False, server_default=""),
    )
    # Nullable on purpose: NULL means "follow detection", which is distinct
    # from an explicit False ("a human said this is not an AI repo").
    op.add_column("target", sa.Column("is_ai_repo_override", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("target", "is_ai_repo_override")
    op.drop_column("target", "is_ai_repo_signals")
    op.drop_column("target", "is_ai_repo")
