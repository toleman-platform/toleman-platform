"""Per-target dependency graph sync status (#330)

Targets now attempt a GitHub Dependency Graph import automatically at
creation. The outcome is persisted here rather than left in a Celery
result, so a reload still shows what happened.

All nullable, no backfill. NULL means "never attempted", which is the
truth for every target that predates this and for every target whose
repo_url is not a github.com repo; it stays distinct from "unavailable",
which means GitHub declined to answer and the inventory is unknown.

Revision ID: b4c9e1d7f206
Revises: a7d4f2e9c1b6
"""
import sqlalchemy as sa
from alembic import op

revision = "b4c9e1d7f206"
down_revision = "a7d4f2e9c1b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("target", sa.Column("dependency_sync_status", sa.String(), nullable=True))
    op.add_column("target", sa.Column("dependency_sync_error", sa.String(), nullable=True))
    op.add_column("target", sa.Column("dependency_sync_at", sa.DateTime(), nullable=True))
    op.add_column("target", sa.Column("dependency_component_count", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("target", "dependency_component_count")
    op.drop_column("target", "dependency_sync_at")
    op.drop_column("target", "dependency_sync_error")
    op.drop_column("target", "dependency_sync_status")
