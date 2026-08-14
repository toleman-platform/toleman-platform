"""add false positive rule (#76)

Revision ID: c4d8e21a9f37
Revises: df303bb8affa
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'c4d8e21a9f37'
down_revision: Union[str, None] = 'df303bb8affa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'falsepositiverule',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workspace_id', sa.Integer(), nullable=False),
        sa.Column('rule_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('tool', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('file_path_pattern', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('source_finding_id', sa.Integer(), nullable=True),
        sa.Column('created_by', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('match_count', sa.Integer(), nullable=False),
        sa.Column('last_matched_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['source_finding_id'], ['finding.id'], ),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_falsepositiverule_workspace_id'), 'falsepositiverule', ['workspace_id'], unique=False)
    op.create_index(op.f('ix_falsepositiverule_rule_id'), 'falsepositiverule', ['rule_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_falsepositiverule_rule_id'), table_name='falsepositiverule')
    op.drop_index(op.f('ix_falsepositiverule_workspace_id'), table_name='falsepositiverule')
    op.drop_table('falsepositiverule')
