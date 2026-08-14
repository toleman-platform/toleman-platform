"""add findingstatelog batch_id (#123)

Revision ID: a1c9e3f7b210
Revises: f2074a4b6a54
Create Date: 2026-08-14 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'a1c9e3f7b210'
down_revision: Union[str, None] = '9dde01b530db'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findingstatelog', sa.Column('batch_id', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.create_index(op.f('ix_findingstatelog_batch_id'), 'findingstatelog', ['batch_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_findingstatelog_batch_id'), table_name='findingstatelog')
    op.drop_column('findingstatelog', 'batch_id')
