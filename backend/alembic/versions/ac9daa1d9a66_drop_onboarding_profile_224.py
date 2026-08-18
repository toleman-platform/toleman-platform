"""drop onboarding profile (issue #224)

The first-run questionnaire and its /onboarding route were removed
entirely -- this drops the table their answers were persisted in
(9f7506526474). Any scanner toggles the questionnaire wrote into
WorkspaceToolConfig (issue #75) are untouched: those rows are the platform's
real, live tool configuration, editable in Tool Marketplace regardless of
what wrote them, and there is no reliable way to tell an onboarding-written
row from a manually-set one after the fact.

Revision ID: ac9daa1d9a66
Revises: 506252dfc555
Create Date: 2026-08-18

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "ac9daa1d9a66"
down_revision: Union[str, None] = "506252dfc555"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index(op.f("ix_onboardingprofile_organization_id"), table_name="onboardingprofile")
    op.drop_table("onboardingprofile")


def downgrade() -> None:
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
    op.create_index(
        op.f("ix_onboardingprofile_organization_id"),
        "onboardingprofile",
        ["organization_id"],
        unique=True,
    )
