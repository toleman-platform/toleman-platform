"""Diff-scoped PR scans (#243): scan scope, files scanned, skipped tools

Adds the columns that let a PR Guardrail scan state how much of the repo it
actually looked at, and which assigned tools had nothing to examine once the
scan was scoped to the PR's changed files.

`tools_skipped` is deliberately its own column rather than a note folded into
`tools_run`. "trivy was skipped because no dependency manifest changed" and
"trivy ran and found nothing" are different claims, and only the second is
evidence of safety; collapsing them is the false-all-clear failure mode
this codebase keeps refusing (see osv_malware.py, issue #229).

`target.diff_scoped_pr_scans` defaults False so no existing target silently
narrows what its PR gate checks when this migration runs.

Revision ID: d9e5b3c7a2f1
Revises: c8a1f2e3d4b5
"""
import sqlalchemy as sa
from alembic import op

revision = "d9e5b3c7a2f1"
down_revision = "c8a1f2e3d4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default on the backfill, then dropped: existing rows need a
    # value, but new rows should take the model's default rather than the
    # database's, so the two can never disagree later.
    op.add_column(
        "prguardrailscan",
        sa.Column("tools_skipped", sa.String(), nullable=False, server_default=""),
    )
    op.add_column(
        "prguardrailscan",
        sa.Column("scan_scope", sa.String(), nullable=False, server_default="full"),
    )
    op.add_column(
        "prguardrailscan",
        sa.Column("files_scanned", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "target",
        sa.Column("diff_scoped_pr_scans", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.alter_column("prguardrailscan", "tools_skipped", server_default=None)
    op.alter_column("prguardrailscan", "scan_scope", server_default=None)
    op.alter_column("prguardrailscan", "files_scanned", server_default=None)
    op.alter_column("target", "diff_scoped_pr_scans", server_default=None)

    # Every pre-existing scan ran against the whole checkout, so "full" is
    # the historically accurate value, not merely a convenient default.


def downgrade() -> None:
    op.drop_column("target", "diff_scoped_pr_scans")
    op.drop_column("prguardrailscan", "files_scanned")
    op.drop_column("prguardrailscan", "scan_scope")
    op.drop_column("prguardrailscan", "tools_skipped")
