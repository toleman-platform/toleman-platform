"""add aibom components (issue #190)

Models and datasets a target depends on, populated during the existing SBOM
generation run. Separate table from sbomcomponent on purpose -- see
AiBomComponent's docstring: a package at a resolved version and a model
reference with genuinely unknown provenance are different things, and sharing
a table would push toward fabricating a version for every model.

Revision ID: 3d006423f58b
Revises: 3d62235d90e0
Create Date: 2026-08-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "3d006423f58b"
down_revision: Union[str, None] = "3d62235d90e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "aibomcomponent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("branch", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("component_type", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("source", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("evidence", sa.String(), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_aibomcomponent_target_id"), "aibomcomponent", ["target_id"])
    # Upsert key: a model is identified by target + branch + name + type.
    # Version is deliberately NOT part of it -- an unpinned reference that
    # later gains a revision is the same dependency, now pinned, not a new
    # one, and the whole point is to be able to see that change.
    op.create_index(
        "ix_aibomcomponent_upsert_key",
        "aibomcomponent",
        ["target_id", "branch", "name", "component_type"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_aibomcomponent_upsert_key", table_name="aibomcomponent")
    op.drop_index(op.f("ix_aibomcomponent_target_id"), table_name="aibomcomponent")
    op.drop_table("aibomcomponent")
