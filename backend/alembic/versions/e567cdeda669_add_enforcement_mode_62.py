"""add enforcement mode (#62)

Revision ID: e567cdeda669
Revises: a1b2c3d4e5f6
Create Date: 2026-08-13 22:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'e567cdeda669'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# NOTE: `alembic revision --autogenerate` also picked up a batch of unrelated
# pre-existing schema drift (a stale `discoveredendpoint` table, missing
# indexes on finding/scan, NOT NULL tightening on platformconfig columns) --
# same drift #61's migration (1aec0547092a) already noted and deliberately
# left out. Not part of issue #62 either; this migration only adds the three
# new nullable enforcement_mode columns below.


def upgrade() -> None:
    op.add_column('workspace', sa.Column('enforcement_mode', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('target', sa.Column('enforcement_mode', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('groups', sa.Column('enforcement_mode', sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    op.drop_column('groups', 'enforcement_mode')
    op.drop_column('target', 'enforcement_mode')
    op.drop_column('workspace', 'enforcement_mode')
