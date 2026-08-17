"""add tool_install_run 216

Revision ID: 506252dfc555
Revises: 9f7506526474
Create Date: 2026-08-17 17:49:23.843575

Hand-trimmed after autogenerate, per the project rule about never shipping a
generated migration unread. `--autogenerate` emitted a great deal more than
this table: it wanted to `drop_table('discoveredendpoint')`, drop an index on
aibomcomponent, flip several platformconfig columns to NOT NULL, convert two
VARCHAR columns to native enums, and add half a dozen indexes.

None of that belongs to this change. It is pre-existing drift between the
models and the deployed schema, and the drop in particular would have
destroyed a real table's data on upgrade. Applying it as a side effect of
adding an unrelated table would be indefensible, so everything except the new
table has been removed. The drift itself is worth its own issue and its own
reviewed migration.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = '506252dfc555'
down_revision: Union[str, None] = '9f7506526474'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'toolinstallrun',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tool', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('package', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('status', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('requested_by_user_id', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('installed_version', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('error', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('output_tail', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.ForeignKeyConstraint(['requested_by_user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_toolinstallrun_tool'), 'toolinstallrun', ['tool'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_toolinstallrun_tool'), table_name='toolinstallrun')
    op.drop_table('toolinstallrun')
