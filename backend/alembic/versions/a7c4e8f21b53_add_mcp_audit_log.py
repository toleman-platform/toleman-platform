"""add mcp audit log (MCP/public-API action logging)

Revision ID: a7c4e8f21b53
Revises: c3a8f1e29b0d
Create Date: 2026-09-11 18:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'a7c4e8f21b53'
down_revision: Union[str, None] = 'c3a8f1e29b0d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'mcpauditlog',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('agent', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('tool', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('summary', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.ForeignKeyConstraint(['target_id'], ['target.id'], ),
        sa.ForeignKeyConstraint(['finding_id'], ['finding.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mcpauditlog_user_id'), 'mcpauditlog', ['user_id'], unique=False)
    op.create_index(op.f('ix_mcpauditlog_tool'), 'mcpauditlog', ['tool'], unique=False)
    op.create_index(op.f('ix_mcpauditlog_created_at'), 'mcpauditlog', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_mcpauditlog_created_at'), table_name='mcpauditlog')
    op.drop_index(op.f('ix_mcpauditlog_tool'), table_name='mcpauditlog')
    op.drop_index(op.f('ix_mcpauditlog_user_id'), table_name='mcpauditlog')
    op.drop_table('mcpauditlog')
