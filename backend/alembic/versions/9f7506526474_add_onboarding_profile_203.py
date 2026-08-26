"""add onboarding profile (issue #203)

First-run questionnaire answers, one row per organization. Every answer
column is nullable on purpose: the wizard is skippable end to end, and a
skipped question means "not stated", which is a different fact from a "no"
and must not be stored as one.

Revision ID: 9f7506526474
Revises: 3d006423f58b
Create Date: 2026-08-17

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "9f7506526474"
down_revision: Union[str, None] = "3d006423f58b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "onboardingprofile",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("languages", sa.String(), nullable=False, server_default=""),
        sa.Column("cloud_providers", sa.String(), nullable=False, server_default=""),
        sa.Column("uses_iac", sa.Boolean(), nullable=True),
        sa.Column("builds_ai_features", sa.Boolean(), nullable=True),
        sa.Column("ships_containers", sa.Boolean(), nullable=True),
        sa.Column("pr_enforcement_preference", sa.String(), nullable=True),
        sa.Column("uses_slack", sa.Boolean(), nullable=True),
        sa.Column("uses_jira", sa.Boolean(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("skipped", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    # One profile per org; the questionnaire is re-runnable, which updates
    # the existing row rather than accumulating a history of answers.
    op.create_index(
        op.f("ix_onboardingprofile_organization_id"),
        "onboardingprofile",
        ["organization_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_onboardingprofile_organization_id"), table_name="onboardingprofile")
    op.drop_table("onboardingprofile")
