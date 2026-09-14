"""Target lifecycle (#273): deactivated_at / deleted_at + audit event types

Until this, a registered target was permanent -- there was no DELETE
endpoint for a target at all (only DELETE /{id}/groups/{group_id}, which
un-tags one), and no flag to stop scanning without removing it.

Two nullable timestamps on `target`, no backfill: NULL means "not in that
state", so every existing target is active and live, which is exactly what
they are today. Deliberately timestamps rather than booleans -- a boolean
plus a "when" column is two fields encoding one fact and they drift; see
Target.deactivated_at's comment in app/models/models.py.

Both are indexed because they are read as a predicate on nearly every
target query in the app (every list, every dashboard/score/report
aggregate, every scan dispatch path), not as display-only fields; the same
reasoning as e2f7a4b9c3d1's index on the ownership facets.

AuthEventType also gains three values (TARGET_DEACTIVATED /
TARGET_REACTIVATED / TARGET_DELETED), but deliberately needs no DDL here:
bb6ff0d694ca stored authauditlog.event_type as a plain varchar rather than
a native Postgres ENUM precisely so a new event type is a Python-side
change only. Contrast c3f7b9a1e4d2, which had to ALTER TYPE because
ignorestatus *is* native -- worth stating explicitly so nobody later
assumes this migration forgot the enum half.

Revision ID: d4b1c7e93a20
Revises: c3e8b7a2d4f1
Create Date: 2026-09-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4b1c7e93a20"
down_revision: Union[str, None] = "9e2a7c41fb08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("target", sa.Column("deactivated_at", sa.DateTime(), nullable=True))
    op.add_column("target", sa.Column("deleted_at", sa.DateTime(), nullable=True))
    op.create_index("ix_target_deactivated_at", "target", ["deactivated_at"])
    op.create_index("ix_target_deleted_at", "target", ["deleted_at"])


def downgrade() -> None:
    op.drop_index("ix_target_deleted_at", table_name="target")
    op.drop_index("ix_target_deactivated_at", table_name="target")
    op.drop_column("target", "deleted_at")
    op.drop_column("target", "deactivated_at")
    # Nothing to undo for the three new AuthEventType values: event_type is
    # a varchar, so any already-written target_deleted / target_deactivated
    # / target_reactivated rows stay readable after a downgrade. That is the
    # right outcome for an audit trail anyway -- a schema rollback must not
    # be a way to make "who deleted this target" unanswerable.
