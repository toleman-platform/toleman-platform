"""add owner_login/owner_type to githubappconfig

The "Manage on GitHub" link (connect-github-card.tsx) needs to know whether
an App is owned by a personal account or an organization to build the right
GitHub settings URL -- github.com/settings/apps/{slug} for a personal App,
github.com/organizations/{owner_login}/settings/apps/{slug} for an org one.
Guessing personal-only 404s for org-owned Apps. These columns are nullable
and backfilled lazily (GET /app via the App's own JWT) rather than requiring
a data migration, since only a live GitHub API call can answer this for
existing rows.

Revision ID: 7a1c9e4f2b3d
Revises: 3262d3d9de62
Create Date: 2026-09-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "7a1c9e4f2b3d"
down_revision: Union[str, None] = "3262d3d9de62"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("githubappconfig", sa.Column("owner_login", sa.String(), nullable=True))
    op.add_column("githubappconfig", sa.Column("owner_type", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("githubappconfig", "owner_type")
    op.drop_column("githubappconfig", "owner_login")
