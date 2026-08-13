"""add cve enrichment cache (#71)

Revision ID: 986121e2b11e
Revises: 1aec0547092a
Create Date: 2026-08-13 19:25:52.068212

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = '986121e2b11e'
down_revision: Union[str, None] = '1aec0547092a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# NOTE: `alembic revision --autogenerate` also picked up a batch of unrelated
# pre-existing schema drift (a stale `discoveredendpoint` table left over
# from a model that no longer exists, missing indexes on finding/scan, and
# NOT NULL tightening on platformconfig columns) -- same drift already
# flagged and deliberately left out of 1aec0547092a (#61). None of that is
# part of issue #71, so it's stripped from this migration too; only the new
# `cveenrichment` table below is issue #71's actual change.


def upgrade() -> None:
    op.create_table('cveenrichment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cve_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
    sa.Column('nvd_description', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_vector', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('cwe_ids', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('nvd_references', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('nvd_found', sa.Boolean(), nullable=False),
    sa.Column('osv_id', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('fixed_versions', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('osv_references', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    sa.Column('osv_found', sa.Boolean(), nullable=False),
    sa.Column('fetched_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cveenrichment_cve_id'), 'cveenrichment', ['cve_id'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_cveenrichment_cve_id'), table_name='cveenrichment')
    op.drop_table('cveenrichment')
