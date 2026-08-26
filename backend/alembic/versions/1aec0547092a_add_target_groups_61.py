"""add target groups (#61)

Revision ID: 1aec0547092a
Revises: 47c27981e4cf
Create Date: 2026-08-13 18:20:21.361425

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '1aec0547092a'
down_revision: Union[str, None] = '47c27981e4cf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# NOTE: `alembic revision --autogenerate` also picked up a batch of unrelated
# schema drift that pre-dates this change (a stale `discoveredendpoint`
# table left over from a model that no longer exists, missing indexes on
# finding/scan, and NOT NULL tightening on platformconfig columns). None of
# that is part of issue #61, so it's deliberately left out of this migration;
# only the two new tables below are issue #61's actual change. That drift
# should be swept up in its own migration separately.


def upgrade() -> None:
    op.create_table('groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('name', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('color', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_groups_workspace_id'), 'groups', ['workspace_id'], unique=False)
    op.create_table('target_group',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ),
    sa.ForeignKeyConstraint(['target_id'], ['target.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('target_id', 'group_id', name='uq_target_group_target_id_group_id')
    )
    op.create_index(op.f('ix_target_group_group_id'), 'target_group', ['group_id'], unique=False)
    op.create_index(op.f('ix_target_group_target_id'), 'target_group', ['target_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_target_group_target_id'), table_name='target_group')
    op.drop_index(op.f('ix_target_group_group_id'), table_name='target_group')
    op.drop_table('target_group')
    op.drop_index(op.f('ix_groups_workspace_id'), table_name='groups')
    op.drop_table('groups')
