"""add baseline_missing to prguardrailscan

PR Guardrail's finding diff (GH-07) compared PR-branch findings against
Open Finding rows already persisted for the target's default branch. When a
target's default branch has never had a completed scan, that comparison set
is empty -- indistinguishable, at the query level, from a default branch
that was scanned and found clean. Every finding in the PR's own (necessarily
whole-repo, on a target's first scan) checkout then looked "net-new", the
same false-positive GH-06 already fixed for the endpoint diff
(_diff_new_endpoints).

baseline_missing records when a scan's finding diff was skipped for this
reason, so the PR comment and PR History can say plainly that "no findings"
here is not yet a real diff against the default branch.

Revision ID: a4d7e0f2c8b1
Revises: b4c9e1d7f206
Create Date: 2026-09-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4d7e0f2c8b1"
down_revision: Union[str, None] = "b4c9e1d7f206"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "prguardrailscan",
        sa.Column("baseline_missing", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("prguardrailscan", "baseline_missing")
