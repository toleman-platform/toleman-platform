"""add pipeline integration batch tracking (#68)

Revision ID: a1b2c3d4e5f6
Revises: 75c290f0d757
Create Date: 2026-08-13 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '75c290f0d757'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'pipelineintegrationbatch',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_by_user_id', sa.Integer(), nullable=False),
        sa.Column('status', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('total', sa.Integer(), nullable=False),
        sa.Column('succeeded', sa.Integer(), nullable=False),
        sa.Column('failed', sa.Integer(), nullable=False),
        sa.Column('already_integrated', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'pipelineintegrationbatchitem',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('batch_id', sa.Integer(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('status', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('error', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('pr_url', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('pr_number', sa.Integer(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['batch_id'], ['pipelineintegrationbatch.id'], ),
        sa.ForeignKeyConstraint(['target_id'], ['target.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_pipelineintegrationbatchitem_batch_id'), 'pipelineintegrationbatchitem', ['batch_id'], unique=False
    )
    op.create_index(
        op.f('ix_pipelineintegrationbatchitem_target_id'), 'pipelineintegrationbatchitem', ['target_id'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_pipelineintegrationbatchitem_target_id'), table_name='pipelineintegrationbatchitem')
    op.drop_index(op.f('ix_pipelineintegrationbatchitem_batch_id'), table_name='pipelineintegrationbatchitem')
    op.drop_table('pipelineintegrationbatchitem')
    op.drop_table('pipelineintegrationbatch')
