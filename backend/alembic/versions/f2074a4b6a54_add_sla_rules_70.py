"""add sla rules (#70)

Revision ID: f2074a4b6a54
Revises: e567cdeda669
Create Date: 2026-08-13 23:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'f2074a4b6a54'
down_revision: Union[str, None] = 'e567cdeda669'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'slarule',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workspace_id', sa.Integer(), nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=True),
        sa.Column('severity', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('days_to_fix', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workspace_id', 'group_id', 'severity', name='uq_sla_rule_workspace_group_severity'),
    )
    op.create_index(op.f('ix_slarule_workspace_id'), 'slarule', ['workspace_id'], unique=False)
    op.create_index(op.f('ix_slarule_group_id'), 'slarule', ['group_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_slarule_group_id'), table_name='slarule')
    op.drop_index(op.f('ix_slarule_workspace_id'), table_name='slarule')
    op.drop_table('slarule')
