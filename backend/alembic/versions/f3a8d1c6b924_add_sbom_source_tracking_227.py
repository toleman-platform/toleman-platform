"""SBOM source tracking (#227): which source reported each component

GitHub's Dependency Graph joins trivy as a second SBOM source. The two see
genuinely different things -- trivy reads dependency manifests, GitHub
reports what those manifests resolve to, including transitives that appear
in no manifest at all -- so which source found a component is information
worth keeping, not an implementation detail.

Every existing row defaults to "trivy", which is accurate: it is the only
source that existed when those rows were written. Backfilling anything else
would relabel them as confirmed by a source that had not run.

sources_run/sources_failed on SbomRun follow the same three-state discipline
as PRGuardrailScan.tools_run/tools_failed: "GitHub's graph is disabled for
this private repo" and "this repo has no dependencies" are different facts,
and a run that cannot distinguish them is a false all-clear.

Revision ID: f3a8d1c6b924
Revises: e2f7a4b9c3d1
"""
import sqlalchemy as sa
from alembic import op

revision = "f3a8d1c6b924"
down_revision = "e2f7a4b9c3d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sbomcomponent",
        sa.Column("source", sa.String(), nullable=False, server_default="trivy"),
    )
    op.add_column(
        "sbomrun",
        sa.Column("sources_run", sa.String(), nullable=False, server_default="trivy"),
    )
    op.add_column(
        "sbomrun",
        sa.Column("sources_failed", sa.String(), nullable=False, server_default=""),
    )
    # server_default dropped after the backfill: existing rows need a value,
    # but new rows should take the model's default so the two can never
    # disagree later. Same pattern as #243's migration.
    op.alter_column("sbomcomponent", "source", server_default=None)
    op.alter_column("sbomrun", "sources_run", server_default=None)
    op.alter_column("sbomrun", "sources_failed", server_default=None)


def downgrade() -> None:
    op.drop_column("sbomrun", "sources_failed")
    op.drop_column("sbomrun", "sources_run")
    op.drop_column("sbomcomponent", "source")
