"""Workspace-scoped risk scoring weights (#201)

One row per (workspace, signal) override. Same shape as slarule/policyrule:
workspace-scoped, created only when someone actually changes something.

No seeding. The absence of a row is what "use the shipped baseline" is
spelled as (app/core/scoring.py::BASELINE_WEIGHTS), the same "None =
inherit" convention workspacetoolconfig and enforcement_mode already use.
Inserting a full set of baseline rows per workspace would make the table
look configured when nothing has been, and would freeze today's calibration
into every existing install so a future change to the baseline could never
reach them.

Revision ID: b7e2a5c34f19
Revises: a4f1c9d80e37
"""
import sqlalchemy as sa
from alembic import op

revision = "b7e2a5c34f19"
down_revision = "a4f1c9d80e37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scoringweight",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        # A native enum, matching what SQLModel generates for every other
        # Enum-typed column in this schema (severity, findingstate,
        # policyruletype, ...) so `alembic upgrade head` and
        # SQLModel.metadata.create_all agree. The labels are the Python
        # member *names*, which is what SQLAlchemy's Enum binds; the wire
        # format stays the lowercase value ("internet_exposure"), exactly as
        # it does for severity.
        #
        # Adding a signal slot later therefore needs an
        # `ALTER TYPE scoringsignal ADD VALUE`, not just a Python enum
        # member -- see c3f7b9a1e4d2, which exists because that step was
        # missed once and 500'd in production.
        sa.Column(
            "signal",
            sa.Enum(
                "SEVERITY",
                "CVSS_EXPLOITABILITY",
                "EPSS",
                "KEV",
                "INTERNET_EXPOSURE",
                "BUSINESS_CRITICALITY",
                "FIXABILITY",
                name="scoringsignal",
            ),
            nullable=False,
        ),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspace.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", "signal", name="uq_scoring_weight_workspace_signal"),
    )
    op.create_index(op.f("ix_scoringweight_workspace_id"), "scoringweight", ["workspace_id"], unique=False)
    op.create_index(op.f("ix_scoringweight_signal"), "scoringweight", ["signal"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scoringweight_signal"), table_name="scoringweight")
    op.drop_index(op.f("ix_scoringweight_workspace_id"), table_name="scoringweight")
    op.drop_table("scoringweight")
    # Same as df303bb8affa: dropping the table leaves the Postgres enum type
    # behind, and a later re-upgrade then fails on "type already exists".
    op.execute("DROP TYPE IF EXISTS scoringsignal")
