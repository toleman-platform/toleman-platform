"""add status_delivery_error to prguardrailscan

Finding GH-04: set_commit_status() is documented "best-effort: never raises",
and it failed open into a container log. Enforcement resolution is carefully
fail-*closed* -- conflicting groups resolve to the most restrictive -- while
the transport carrying that decision to GitHub was fail-open and silent. If
an installation token breaks, PRs stop being marked and nobody is told.

Posting stays fail-open (a GitHub outage must not discard a scan that already
produced real findings), but the reason is now recorded here and rendered in
PR History next to the decision it failed to deliver.

Revision ID: c8a1f2e3d4b5
Revises: b7e4c9a1d2f3
Create Date: 2026-08-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c8a1f2e3d4b5"
down_revision: Union[str, None] = "b7e4c9a1d2f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default="" so existing rows read as "no delivery problem"
    # rather than NULL -- the model declares this a non-Optional str, and a
    # NULL would render as a phantom error on every historical scan.
    op.add_column(
        "prguardrailscan",
        sa.Column("status_delivery_error", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("prguardrailscan", "status_delivery_error")
