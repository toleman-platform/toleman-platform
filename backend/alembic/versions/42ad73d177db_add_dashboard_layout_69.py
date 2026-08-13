"""add dashboard layout (#69)

Revision ID: 42ad73d177db
Revises: f2074a4b6a54
Create Date: 2026-08-13 23:24:44.742207

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '42ad73d177db'
down_revision: Union[str, None] = 'f2074a4b6a54'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Hand-trimmed from `alembic revision --autogenerate`: the raw diff also
    # picked up unrelated pre-existing schema drift (index/column changes on
    # finding/scan/platformconfig/slarule, a leftover `discoveredendpoint`
    # table) that isn't part of issue #69 -- only the new DashboardLayout
    # table belongs in this migration.
    op.create_table(
        'dashboardlayout',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('widgets', sa.JSON(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_dashboardlayout_user_id'), 'dashboardlayout', ['user_id'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_dashboardlayout_user_id'), table_name='dashboardlayout')
    op.drop_table('dashboardlayout')
