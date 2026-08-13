"""add slack/jira integration fields to platformconfig (#74)

Revision ID: b3f9d2a7c1e4
Revises: 42ad73d177db
Create Date: 2026-08-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'b3f9d2a7c1e4'
down_revision: Union[str, None] = '42ad73d177db'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('platformconfig', sa.Column('slack_webhook_url', sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default=''))
    op.add_column('platformconfig', sa.Column('jira_url', sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default=''))
    op.add_column('platformconfig', sa.Column('jira_api_token', sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default=''))
    op.add_column('platformconfig', sa.Column('jira_project_key', sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default=''))
    op.add_column('platformconfig', sa.Column('jira_issue_type', sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default='Task'))
    op.add_column('platformconfig', sa.Column('jira_auto_create_severity', sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    op.drop_column('platformconfig', 'jira_auto_create_severity')
    op.drop_column('platformconfig', 'jira_issue_type')
    op.drop_column('platformconfig', 'jira_project_key')
    op.drop_column('platformconfig', 'jira_api_token')
    op.drop_column('platformconfig', 'jira_url')
    op.drop_column('platformconfig', 'slack_webhook_url')
