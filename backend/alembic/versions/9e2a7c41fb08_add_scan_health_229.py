"""Scan health verdict on scan (#229)

Adds scan.health ("healthy" | "suspect" | "unknown") and scan.health_note.

A scan row already records whether the run *finished* (`status`) and why it
did not (`error`). Neither can express the failure #229 is about: a run that
finished, exited 0 and emitted valid JSON while having read a half-written
trivy vulnerability database, so a repository with five live High/Medium
CVEs came back with zero findings and the ingestion pipeline mitigated all
five. These two columns carry the separate question of whether the run can
be trusted to have checked what it claims, and what was done about it.

Defaults to "unknown", not "healthy": every row written before this existed
was never assessed, and back-filling them as healthy would assert a check
nobody performed -- the exact overclaim the issue is about. "unknown" also
stays distinct from "suspect" so a year of legitimate scan history does not
render as a wall of warnings users learn to scroll past.

Revision ID: 9e2a7c41fb08
Revises: c3e8b7a2d4f1
"""
import sqlalchemy as sa
from alembic import op

revision = "9e2a7c41fb08"
down_revision = "b1d4f7a09c62"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan",
        sa.Column("health", sa.String(), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "scan",
        sa.Column("health_note", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("scan", "health_note")
    op.drop_column("scan", "health")
