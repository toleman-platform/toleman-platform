"""add target api_base_url for active API scanning (issue 72)

Revision ID: 9dde01b530db
Revises: df303bb8affa
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9dde01b530db'
down_revision: Union[str, None] = '4acb8bec28d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('target', sa.Column('api_base_url', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('target', 'api_base_url')
