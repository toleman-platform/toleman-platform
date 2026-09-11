"""add auth audit log (login/logout/permission changes)

Revision ID: bb6ff0d694ca
Revises: 7a1c9e4f2b3d
Create Date: 2026-09-11 09:41:06.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'bb6ff0d694ca'
down_revision: Union[str, None] = '7a1c9e4f2b3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'authauditlog',
        sa.Column('id', sa.Integer(), nullable=False),
        # Plain varchar, not a native Postgres ENUM (same choice the initial
        # schema already made for e.g. prguardrailscan.status): a new
        # AuthEventType value later needs no ALTER TYPE migration, only a
        # Python-side change.
        sa.Column('event_type', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('actor', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('target_email', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('detail', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('ip_address', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_authauditlog_event_type'), 'authauditlog', ['event_type'], unique=False)
    op.create_index(op.f('ix_authauditlog_actor'), 'authauditlog', ['actor'], unique=False)
    op.create_index(op.f('ix_authauditlog_created_at'), 'authauditlog', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_authauditlog_created_at'), table_name='authauditlog')
    op.drop_index(op.f('ix_authauditlog_actor'), table_name='authauditlog')
    op.drop_index(op.f('ix_authauditlog_event_type'), table_name='authauditlog')
    op.drop_table('authauditlog')
