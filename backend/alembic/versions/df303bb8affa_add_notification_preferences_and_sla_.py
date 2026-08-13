"""add notification preferences and sla breach dedup (issue 73)

Revision ID: df303bb8affa
Revises: b3f9d2a7c1e4
Create Date: 2026-08-14 03:40:27.194858

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'df303bb8affa'
down_revision: Union[str, None] = 'b3f9d2a7c1e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'notificationpreference',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('channel', sa.Enum('EMAIL', 'SLACK', name='notificationchannel'), nullable=False),
        sa.Column('event_type', sa.Enum('CRITICAL_FINDING', 'KEV_CVE', 'SLA_BREACH', 'SCAN_FAILURE', name='notificationeventtype'), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'channel', 'event_type', name='uq_notification_pref_user_channel_event'),
    )
    op.create_index(op.f('ix_notificationpreference_user_id'), 'notificationpreference', ['user_id'], unique=False)
    op.add_column('finding', sa.Column('sla_breach_notified_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('finding', 'sla_breach_notified_at')
    op.drop_index(op.f('ix_notificationpreference_user_id'), table_name='notificationpreference')
    op.drop_table('notificationpreference')
    op.execute('DROP TYPE IF EXISTS notificationeventtype')
    op.execute('DROP TYPE IF EXISTS notificationchannel')
