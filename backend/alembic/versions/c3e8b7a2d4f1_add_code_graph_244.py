"""Code graph for diff-scoped blast radius (#244)

New `codegraph` table: one row per target holding a Python import graph as
`{file_path: [files that import it]}`, keyed by the commit it was built
from.

`commit_sha` is indexed and matched exactly on read. A graph built from a
different commit describes a different import structure, and reusing it
would narrow a PR scan against a tree that no longer exists -- so a miss
rebuilds from the checkout the scan already has rather than falling back to
scanning everything.

No backfill and no default row: absence means "no graph for this target
yet", which app.core.code_graph resolves by building one. Nothing about
existing targets changes when this runs.

Revision ID: c3e8b7a2d4f1
Revises: a7d4f2e9c1b6
Create Date: 2026-08-22

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
import sqlmodel

revision: str = "c3e8b7a2d4f1"
down_revision: Union[str, None] = "a7d4f2e9c1b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "codegraph",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("commit_sha", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("edges", sa.JSON(), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("built_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.UniqueConstraint("target_id"),
    )
    op.create_index("ix_codegraph_target_id", "codegraph", ["target_id"])
    op.create_index("ix_codegraph_commit_sha", "codegraph", ["commit_sha"])

    # server_default was only needed to satisfy the NOT NULL on any row an
    # in-flight write might create during the migration; new rows take the
    # model's default so the two can never disagree later. Same treatment as
    # #243's columns.
    op.alter_column("codegraph", "file_count", server_default=None)
    op.alter_column("codegraph", "built_at", server_default=None)

    # Scope disclosure on the scan row itself. Existing scans get 0/"" --
    # historically accurate, since none of them had a blast radius computed.
    op.add_column(
        "prguardrailscan",
        sa.Column("blast_radius_files", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "prguardrailscan",
        sa.Column("scope_reason", sa.String(), nullable=False, server_default=""),
    )
    op.alter_column("prguardrailscan", "blast_radius_files", server_default=None)
    op.alter_column("prguardrailscan", "scope_reason", server_default=None)


def downgrade() -> None:
    op.drop_column("prguardrailscan", "scope_reason")
    op.drop_column("prguardrailscan", "blast_radius_files")
    op.drop_index("ix_codegraph_commit_sha", table_name="codegraph")
    op.drop_index("ix_codegraph_target_id", table_name="codegraph")
    op.drop_table("codegraph")
