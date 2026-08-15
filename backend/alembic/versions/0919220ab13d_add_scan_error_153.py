"""add scan.error (#153)

Revision ID: 0919220ab13d
Revises: a1c9e3f7b210
Create Date: 2026-08-15 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0919220ab13d'
down_revision: Union[str, None] = 'a1c9e3f7b210'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scan', sa.Column('error', sa.String(), nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('scan', 'error')
