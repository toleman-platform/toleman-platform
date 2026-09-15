"""Per-tool execution log on prguardrailscan (#501)

tools_run, tools_failed and tools_skipped are name lists. A reviewer
looking at a slow or failed PR check could see which tools took part and
nothing about what they did: no durations, no per-tool finding counts, and
no skip reasons -- the executor computes those and dropped them on the
floor.

Stored as a JSON array of {tool, status, seconds, findings, detail} in a
text column, matching how the three CSV columns beside it already
denormalise the same data. It is read whole, written once, never queried by
field and never joined, so a child table would buy nothing.

Defaults to "" rather than "[]" so a row that predates this migration is
distinguishable from a scan that genuinely logged nothing. The API renders
both as an empty log; the difference matters only when someone asks why an
old scan has no timings.

Revision ID: b6d2f8a41c79
Revises: a1c8e5f70d34
"""
import sqlalchemy as sa
from alembic import op

revision = "b6d2f8a41c79"
down_revision = "a1c8e5f70d34"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "prguardrailscan",
        sa.Column("tool_log", sa.String(), nullable=False, server_default=""),
    )
    op.alter_column("prguardrailscan", "tool_log", server_default=None)


def downgrade() -> None:
    op.drop_column("prguardrailscan", "tool_log")
