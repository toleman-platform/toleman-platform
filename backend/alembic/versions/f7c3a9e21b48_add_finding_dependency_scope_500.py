"""Dependency scope on finding (#500)

#488 made trivy scan npm devDependencies, which took this repo from 0 npm
findings to 8 -- one critical, two high, every one of them a dev
dependency. They then sat alongside runtime-dependency CVEs with nothing
distinguishing them, so a critical in a test runner ranked identically to a
critical in a shipped library.

Defaults to "unknown" rather than "runtime", and that choice is the whole
point of the column. Every existing row predates the field and genuinely
has no answer; so does every ecosystem whose manifest cannot express the
distinction. Backfilling those as runtime would misrank the entire backlog
in the opposite direction from the bug being fixed, and backfilling as
development would hide real runtime risk. "Unknown" is the honest answer
and the only one that does not invent data.

Indexed because filtering triage to runtime-only is the reason the column
exists.

Revision ID: f7c3a9e21b48
Revises: e8a4c1f36d92
"""
import sqlalchemy as sa
from alembic import op

revision = "f7c3a9e21b48"
down_revision = "e8a4c1f36d92"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default carries the backfill for existing rows and is then
    # dropped, so the application's own default is what applies to new
    # inserts and the model stays the single source of truth. Same pattern
    # as the other add-column migrations here.
    op.add_column(
        "finding",
        sa.Column("dependency_scope", sa.String(), nullable=False, server_default="unknown"),
    )
    op.alter_column("finding", "dependency_scope", server_default=None)
    op.create_index("ix_finding_dependency_scope", "finding", ["dependency_scope"])


def downgrade() -> None:
    op.drop_index("ix_finding_dependency_scope", table_name="finding")
    op.drop_column("finding", "dependency_scope")
