"""add tools_run/tools_failed to prguardrailscan

PR Guardrail became multi-tool (finding GH-01): it now runs whatever tools a
workspace has assigned to the pr_guardrail surface instead of a hardcoded
semgrep. Once the tool set is operator-configurable, "0 net-new findings"
is only meaningful alongside what was actually run -- and a scan where an
assigned tool failed must be distinguishable from a clean one.

Revision ID: b7e4c9a1d2f3
Revises: f1c2d3e4a5b6
Create Date: 2026-08-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7e4c9a1d2f3"
down_revision: Union[str, None] = "f1c2d3e4a5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default="" so existing rows get a real empty string rather than
    # NULL -- the model declares these non-Optional str, and a NULL would
    # surface as None on every historical scan and break "which tools ran"
    # rendering for them.
    op.add_column(
        "prguardrailscan",
        sa.Column("tools_run", sa.String(), nullable=False, server_default=""),
    )
    op.add_column(
        "prguardrailscan",
        sa.Column("tools_failed", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("prguardrailscan", "tools_failed")
    op.drop_column("prguardrailscan", "tools_run")
