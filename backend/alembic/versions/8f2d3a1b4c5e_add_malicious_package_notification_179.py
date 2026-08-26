"""add malicious_package notification event type (issue #179)

Adds MALICIOUS_PACKAGE to the native notificationeventtype Postgres enum so
the #179 notification can be subscribed to independently of critical_finding.
Adding an enum member is a manual op.execute; Alembic autogenerate does not
detect new enum values (only new columns/tables), and the value must exist in
the DB type before the model can write it.

Revision ID: 8f2d3a1b4c5e
Revises: ac9daa1d9a66
Create Date: 2026-08-19

"""
from typing import Sequence, Union

from alembic import op

revision: str = "8f2d3a1b4c5e"
down_revision: Union[str, None] = "f3a8d1c6b924"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres >= 12 allows ADD VALUE inside a transaction (we run postgres:16).
    # IF NOT EXISTS keeps this idempotent across a re-run of the migration.
    op.execute("ALTER TYPE notificationeventtype ADD VALUE IF NOT EXISTS 'MALICIOUS_PACKAGE'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE, so this is intentionally a
    # no-op: removing the value would require recreating the type (and every
    # column/table depending on it) with the old value set. Downgrades across
    # enum-value additions are documented as non-reversible here.
    pass
