"""add siem export fields to platformconfig (#114)

Revision ID: 0df342949bde
Revises: 3545a19ef2ea
Create Date: 2026-08-15 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0df342949bde'
down_revision: Union[str, None] = '3545a19ef2ea'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('platformconfig', sa.Column('siem_webhook_url', sa.String(), nullable=False, server_default=''))
    op.add_column('platformconfig', sa.Column('siem_export_severity', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('platformconfig', 'siem_export_severity')
    op.drop_column('platformconfig', 'siem_webhook_url')
