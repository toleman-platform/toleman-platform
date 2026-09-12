"""add REVOKED to the ignorestatus Postgres enum

The Python IgnoreStatus enum (app/models/models.py) has carried a REVOKED
member since revoke_ignore/#401 shipped (a previously-approved ignore a
reviewer later undid, its own terminal state rather than resetting to
NONE), but the native Postgres enum type this column uses was never
migrated to add the matching value -- the initial schema migration only
created NONE/REQUESTED/APPROVED/REJECTED. Every query filtering or writing
ignore_status = REVOKED has been failing in production with
psycopg.errors.InvalidTextRepresentation ever since: GET
/api/pr-guardrail/ignore-requests/history 500s outright (its WHERE ...
IN (..., 'REVOKED') is rejected before any row is even read), and
revoke_ignore itself would fail the same way trying to write the value.

Same manual-op.execute pattern as 8f2d3a1b4c5e (notificationeventtype):
Alembic autogenerate does not detect new enum values, only new
columns/tables.

Revision ID: c3f7b9a1e4d2
Revises: a7c4e8f21b53
Create Date: 2026-09-12

"""
from typing import Sequence, Union

from alembic import op

revision: str = "c3f7b9a1e4d2"
down_revision: Union[str, None] = "a7c4e8f21b53"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres >= 12 allows ADD VALUE inside a transaction (we run postgres:16).
    # IF NOT EXISTS keeps this idempotent across a re-run of the migration.
    op.execute("ALTER TYPE ignorestatus ADD VALUE IF NOT EXISTS 'REVOKED'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE, so this is intentionally a
    # no-op: removing the value would require recreating the type (and every
    # column/table depending on it) with the old value set. Downgrades across
    # enum-value additions are documented as non-reversible here.
    pass
