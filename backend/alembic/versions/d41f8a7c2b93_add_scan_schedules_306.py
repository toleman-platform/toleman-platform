"""add configurable scan schedules (#306)

Backs app.models.models.ScanSchedule: workspace-scoped (and optionally
target-scoped) rows saying which scan type runs, how often, and whether it
runs at all, replacing the two hardcoded `timedelta(hours=24)` entries that
used to be the entire scheduling story in celery_app.conf.beat_schedule.

No data migration and no backfill: an install that has configured nothing
has no rows, and app.core.scan_schedules.SHIPPED_DEFAULTS reproduces
exactly today's behaviour (full scans every 24h; active API scanning off,
which is also what it was before this issue, since it was never scheduled
at all). The dispatcher materialises the workspace-default rows on its
first tick so there is somewhere to record last_run_at/next_run_at.

Revision ID: d41f8a7c2b93
Revises: c3e8b7a2d4f1
Create Date: 2026-09-13 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d41f8a7c2b93"
down_revision: Union[str, None] = "d4b1c7e93a20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scanschedule",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        # Nullable: NULL is the workspace-wide default for this scan type.
        sa.Column("target_id", sa.Integer(), nullable=True),
        # sa.Enum rather than AutoString, matching what SQLModel actually
        # maps a Python Enum field to (and therefore what the ORM will bind
        # against); the same shape NotificationPreference's channel/
        # event_type columns use. Postgres gets a real enum type, which is
        # why downgrade() has to drop it explicitly below.
        sa.Column("scan_type", sa.Enum("FULL_SCAN", "API_SCAN", name="scanscheduletype"), nullable=False),
        # Both nullable: NULL means "inherit", never "off" / "zero hours".
        sa.Column("interval_hours", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        # NULL means "has never fired", a state the UI renders explicitly.
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_dispatched_count", sa.Integer(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspace.id"]),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workspace_id", "target_id", "scan_type", name="uq_scan_schedule_workspace_target_type"
        ),
    )
    op.create_index(op.f("ix_scanschedule_workspace_id"), "scanschedule", ["workspace_id"], unique=False)
    op.create_index(op.f("ix_scanschedule_target_id"), "scanschedule", ["target_id"], unique=False)
    op.create_index(op.f("ix_scanschedule_scan_type"), "scanschedule", ["scan_type"], unique=False)
    # The dispatcher's hot path is "every row whose next_run_at has passed",
    # run every few minutes forever; indexed so that stays one cheap range
    # scan rather than a full table scan per tick.
    op.create_index(op.f("ix_scanschedule_next_run_at"), "scanschedule", ["next_run_at"], unique=False)
    # At most one workspace-default row per (workspace, scan type). The
    # UniqueConstraint above cannot express this: Postgres treats NULL as
    # distinct, so two target_id-NULL rows slip straight through it. A
    # duplicate here is not cosmetic -- both rows come due together, both
    # cover every target in the workspace, and every target gets scanned
    # twice per cycle from then on, invisibly, because every read path takes
    # .first(). The writer that can produce one (ensure_workspace_default_
    # rows) runs unattended every few minutes, so this is enforced in the
    # schema rather than left to a lookup-then-insert check.
    op.create_index(
        "uq_scan_schedule_workspace_default",
        "scanschedule",
        ["workspace_id", "scan_type"],
        unique=True,
        postgresql_where=sa.text("target_id IS NULL"),
        sqlite_where=sa.text("target_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_scan_schedule_workspace_default", table_name="scanschedule")
    op.drop_index(op.f("ix_scanschedule_next_run_at"), table_name="scanschedule")
    op.drop_index(op.f("ix_scanschedule_scan_type"), table_name="scanschedule")
    op.drop_index(op.f("ix_scanschedule_target_id"), table_name="scanschedule")
    op.drop_index(op.f("ix_scanschedule_workspace_id"), table_name="scanschedule")
    op.drop_table("scanschedule")
    op.execute("DROP TYPE IF EXISTS scanscheduletype")
