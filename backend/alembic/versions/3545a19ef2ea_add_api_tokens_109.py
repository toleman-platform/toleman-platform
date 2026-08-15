"""add api tokens (#109)

Revision ID: 3545a19ef2ea
Revises: 0919220ab13d
Create Date: 2026-08-15 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3545a19ef2ea'
down_revision: Union[str, None] = '0919220ab13d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'apitoken',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('token_prefix', sa.String(), nullable=False),
        sa.Column('scope', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index(op.f('ix_apitoken_user_id'), 'apitoken', ['user_id'], unique=False)
    op.create_index(op.f('ix_apitoken_token_hash'), 'apitoken', ['token_hash'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_apitoken_token_hash'), table_name='apitoken')
    op.drop_index(op.f('ix_apitoken_user_id'), table_name='apitoken')
    op.drop_table('apitoken')
