"""Per-workspace GitHub App registration (#506)

A workspace may now register its own GitHub App instead of always sharing
the platform-wide one. Nullable, no backfill: every existing
GitHubAppConfig row stays NULL, which is the correct reading -- it becomes
the platform-level default App every workspace that hasn't registered its
own continues to use.

Revision ID: f589f48b137b
Revises: b6d2f8a41c79
"""
import sqlalchemy as sa
from alembic import op

revision = "f589f48b137b"
down_revision = "b6d2f8a41c79"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("githubappconfig", sa.Column("workspace_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_githubappconfig_workspace_id",
        "githubappconfig",
        "workspace",
        ["workspace_id"],
        ["id"],
    )
    op.create_index(
        "ix_githubappconfig_workspace_id", "githubappconfig", ["workspace_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_githubappconfig_workspace_id", table_name="githubappconfig")
    op.drop_constraint("fk_githubappconfig_workspace_id", "githubappconfig", type_="foreignkey")
    op.drop_column("githubappconfig", "workspace_id")
