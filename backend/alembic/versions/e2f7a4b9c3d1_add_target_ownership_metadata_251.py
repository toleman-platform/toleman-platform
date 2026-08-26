"""Target ownership metadata (#251): owner, environment, lifecycle

criticality_weight already multiplies every finding's priority_score, but
nothing recorded why a target is critical; the number was an assertion
nobody could audit. These three columns make it explainable and give the
findings list the facets people actually filter by.

All nullable, no backfill. NULL means "not recorded", which stays distinct
from any real value an operator sets; guessing "production" for existing
targets would be inventing data.

Revision ID: e2f7a4b9c3d1
Revises: d9e5b3c7a2f1
"""
import sqlalchemy as sa
from alembic import op

revision = "e2f7a4b9c3d1"
down_revision = "d9e5b3c7a2f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("target", sa.Column("owner", sa.String(), nullable=True))
    op.add_column("target", sa.Column("environment", sa.String(), nullable=True))
    op.add_column("target", sa.Column("lifecycle", sa.String(), nullable=True))
    # Indexed because these are filter facets, not display-only fields.
    op.create_index("ix_target_environment", "target", ["environment"])
    op.create_index("ix_target_owner", "target", ["owner"])


def downgrade() -> None:
    op.drop_index("ix_target_owner", table_name="target")
    op.drop_index("ix_target_environment", table_name="target")
    op.drop_column("target", "lifecycle")
    op.drop_column("target", "environment")
    op.drop_column("target", "owner")
