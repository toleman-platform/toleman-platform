"""add workspace tool config for tool marketplace usage assignment (issue 75)

Revision ID: c8a1f4e6b2d9
Revises: df303bb8affa
Create Date: 2026-08-14 05:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c8a1f4e6b2d9'
down_revision: Union[str, None] = 'df303bb8affa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'workspacetoolconfig',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workspace_id', sa.Integer(), nullable=False),
        sa.Column('tool', sa.String(), nullable=False),
        sa.Column('on_demand_scan', sa.Boolean(), nullable=False),
        sa.Column('ci_pipeline', sa.Boolean(), nullable=False),
        sa.Column('api_scan', sa.Boolean(), nullable=False),
        sa.Column('pr_guardrail', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workspace_id', 'tool', name='uq_workspace_tool_config_workspace_tool'),
    )
    op.create_index(op.f('ix_workspacetoolconfig_workspace_id'), 'workspacetoolconfig', ['workspace_id'], unique=False)
    op.create_index(op.f('ix_workspacetoolconfig_tool'), 'workspacetoolconfig', ['tool'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_workspacetoolconfig_tool'), table_name='workspacetoolconfig')
    op.drop_index(op.f('ix_workspacetoolconfig_workspace_id'), table_name='workspacetoolconfig')
    op.drop_table('workspacetoolconfig')
