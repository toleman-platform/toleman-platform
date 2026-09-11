"""add snippet scan run (MCP pre-commit vulnerability check)

Revision ID: c3a8f1e29b0d
Revises: bb6ff0d694ca
Create Date: 2026-09-11 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'c3a8f1e29b0d'
down_revision: Union[str, None] = 'bb6ff0d694ca'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'snippetscanrun',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('filename', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        # Plain varchar, not a native Postgres ENUM, same "running"/
        # "completed"/"failed" convention as scan.status/discoveryrun.status.
        sa.Column('status', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('findings_json', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('error', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_snippetscanrun_user_id'), 'snippetscanrun', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_snippetscanrun_user_id'), table_name='snippetscanrun')
    op.drop_table('snippetscanrun')
