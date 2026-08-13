"""add pipeline integration fields to target (#66)

Revision ID: 75c290f0d757
Revises: 986121e2b11e
Create Date: 2026-08-13 20:01:40.633292

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = '75c290f0d757'
down_revision: Union[str, None] = '986121e2b11e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# NOTE: `alembic revision --autogenerate` also picked up the same
# pre-existing schema drift already flagged and stripped out of every prior
# migration since #61 (stale `discoveredendpoint` table, missing finding/scan
# indexes, NOT NULL tightening on platformconfig columns) -- none of that is
# part of issue #66, so only the two new `target` columns below are kept.


def upgrade() -> None:
    op.add_column('target', sa.Column('pipeline_integrated', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('target', sa.Column('pipeline_pr_url', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    # Server default only needed to backfill existing rows -- match the
    # model's plain Python-side default (SQLModel field default, not a DB
    # default) going forward, same convention used elsewhere in this file's
    # sibling migrations.
    op.alter_column('target', 'pipeline_integrated', server_default=None)


def downgrade() -> None:
    op.drop_column('target', 'pipeline_pr_url')
    op.drop_column('target', 'pipeline_integrated')
