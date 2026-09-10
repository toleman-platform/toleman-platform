"""add force and skipped_webhook_reachable to pipelineintegrationbatch

#245's double-scan gap: server-side PR Guardrail already scans every PR
once GitHub can reach this backend (app.core.github_app.webhook_reachable),
so Pipeline Integration's Actions-based path adds a redundant second scan
of the same PRs on top of it. `force` records whether a bulk/mass rollout
batch explicitly opted into that redundancy anyway;
`skipped_webhook_reachable` counts how many of its items were skipped for
this reason instead of run, mirroring the existing `already_integrated`
counter.

Revision ID: 3262d3d9de62
Revises: a4d7e0f2c8b1
Create Date: 2026-09-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "3262d3d9de62"
down_revision: Union[str, None] = "a4d7e0f2c8b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pipelineintegrationbatch",
        sa.Column("force", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "pipelineintegrationbatch",
        sa.Column("skipped_webhook_reachable", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("pipelineintegrationbatch", "skipped_webhook_reachable")
    op.drop_column("pipelineintegrationbatch", "force")
