"""Operator-declared scan scope on apiendpoint (#469)

Active API scanning had no way to say "never touch this endpoint". The only
narrowing available was endpoint_ids on a single scan request, which is an
opt-in selection rather than a standing rule, so a scheduled scan or a
caller that omitted it went back to hitting everything discovered.

excluded defaults to false, so this migration changes no existing target's
behaviour on its own; what it adds is somewhere for an operator's decision
to live across discovery runs. Discovery keeps re-upserting an endpoint it
still finds (see core/discovery_ingestion.upsert_endpoints), and that
upsert must not reset these columns -- the whole point is that the decision
outlives the next re-scan.

Indexed because build_scan_urls filters on it for every endpoint of a
target on every scan dispatch.

Revision ID: c3f9a1b47d08
Revises: b7e2a5c34f19
"""
import sqlalchemy as sa
from alembic import op

revision = "c3f9a1b47d08"
down_revision = "b7e2a5c34f19"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default is set for the backfill of existing rows and then
    # dropped: without it the ALTER cannot fill in a NOT NULL column on a
    # populated table, and leaving it in place afterwards would let a row
    # be inserted without the application's own default ever being
    # consulted, which is how the model and the schema drift apart.
    op.add_column(
        "apiendpoint",
        sa.Column("excluded", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("apiendpoint", "excluded", server_default=None)
    op.add_column("apiendpoint", sa.Column("exclusion_reason", sa.String(), nullable=True))
    op.create_index("ix_apiendpoint_excluded", "apiendpoint", ["excluded"])


def downgrade() -> None:
    op.drop_index("ix_apiendpoint_excluded", table_name="apiendpoint")
    op.drop_column("apiendpoint", "exclusion_reason")
    op.drop_column("apiendpoint", "excluded")
