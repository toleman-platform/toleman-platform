"""add reject_reason to prguardrailfinding

The Approval Queue's Reject action (app/api/pr_guardrail.py's
reject_ignore) accepted no reason, so a security engineer turning down a
developer's ignore request left the History tab with nothing but a
verdict -- a gap in the same audit trail PR Guardrail otherwise sells.
reject_reason is that reason, going forward required by the endpoint
itself (400 without one), not by a NOT NULL constraint here: existing rows
already rejected before this column existed have no reason to backfill,
and a NOT NULL column would force either a fabricated backfill value or a
migration that fails on any live rejected-history row.

Revision ID: e8a4c1f36d92
Revises: e1a4d9c72f6b
Create Date: 2026-09-15
"""
import sqlalchemy as sa
from alembic import op

revision = "e8a4c1f36d92"
down_revision = "e1a4d9c72f6b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("prguardrailfinding", sa.Column("reject_reason", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("prguardrailfinding", "reject_reason")
