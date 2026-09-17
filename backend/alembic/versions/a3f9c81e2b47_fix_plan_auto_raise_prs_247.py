"""Fix Plan PR automation: auto-raise toggle + raised-PR/batch tracking (#247 follow-up)

Adds `target.auto_raise_fix_prs` (defaults False, same "no existing target
silently opts into unattended repo writes" reasoning as
d9e5b3c7a2f1_add_diff_scoped_pr_scan_fields_243's diff_scoped_pr_scans), and
three tables:

* `remediationfixpr` -- one row per PR app.core.remediation_autofix.
  raise_package_fix_pr actually opened for a Fix Plan package upgrade,
  whether raised by hand or by the auto-raise sweep. Both the manual
  "Raise PR" endpoint and the sweep read this to recognize a package as
  already addressed, instead of polling GitHub's PR state.
* `remediationprbatch` / `remediationprbatchitem` -- tracks a single async
  "Raise all" run, same shape as a1b2c3d4e5f6_add_pipeline_integration_batch_68's
  PipelineIntegrationBatch/PipelineIntegrationBatchItem.

Revision ID: a3f9c81e2b47
Revises: 7cd6cc7045fb
"""
import sqlalchemy as sa
import sqlmodel
from alembic import op

revision = "a3f9c81e2b47"
down_revision = "7cd6cc7045fb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "target",
        sa.Column("auto_raise_fix_prs", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("target", "auto_raise_fix_prs", server_default=None)

    op.create_table(
        "remediationfixpr",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("package", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("ecosystem", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("upgrade_to", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("finding_ids", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("pr_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("branch", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("raised_by", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_remediationfixpr_target_id"), "remediationfixpr", ["target_id"], unique=False)
    op.create_index(op.f("ix_remediationfixpr_package"), "remediationfixpr", ["package"], unique=False)

    op.create_table(
        "remediationprbatch",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("succeeded", sa.Integer(), nullable=False),
        sa.Column("failed", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_remediationprbatch_target_id"), "remediationprbatch", ["target_id"], unique=False)

    op.create_table(
        "remediationprbatchitem",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("package", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("error", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("pr_url", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["batch_id"], ["remediationprbatch.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_remediationprbatchitem_batch_id"), "remediationprbatchitem", ["batch_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_remediationprbatchitem_batch_id"), table_name="remediationprbatchitem")
    op.drop_table("remediationprbatchitem")
    op.drop_index(op.f("ix_remediationprbatch_target_id"), table_name="remediationprbatch")
    op.drop_table("remediationprbatch")
    op.drop_index(op.f("ix_remediationfixpr_package"), table_name="remediationfixpr")
    op.drop_index(op.f("ix_remediationfixpr_target_id"), table_name="remediationfixpr")
    op.drop_table("remediationfixpr")
    op.drop_column("target", "auto_raise_fix_prs")
