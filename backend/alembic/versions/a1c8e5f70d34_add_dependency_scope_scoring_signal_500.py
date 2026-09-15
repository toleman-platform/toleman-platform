"""Add the dependency_scope scoring signal slot (#500)

ScoringSignal is a native Postgres enum -- SQLModel generates it that way,
and b7e2a5c34f19 (which created scoringweight) notes that adding a slot
therefore needs an ALTER TYPE and not just a Python enum member. This is
that ALTER TYPE.

No scoringweight rows are seeded. Absence of a row means "use the shipped
baseline", and app.core.scoring.BASELINE_WEIGHTS baselines this slot at
0.0, so an install that configures nothing scores exactly as it did before
this migration -- the same property every other signal added by #201 has.

IF NOT EXISTS because this is idempotent under a re-run, and because a
partially-applied migration on a database where someone had already added
the label by hand should not be an outage.

Postgres allows ADD VALUE inside a transaction as long as the new label is
not *used* in that same transaction, which is why this migration only adds
it and seeds nothing.

Revision ID: a1c8e5f70d34
Revises: f7c3a9e21b48
"""
from alembic import op

revision = "a1c8e5f70d34"
down_revision = "f7c3a9e21b48"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE scoringsignal ADD VALUE IF NOT EXISTS 'DEPENDENCY_SCOPE'")


def downgrade() -> None:
    # Postgres cannot drop a value from an enum type. Removing it would mean
    # recreating the type and rewriting every column that uses it, which is
    # a far bigger hazard than leaving one unused label in place -- and an
    # unused label is inert: nothing reads it unless a scoringweight row
    # names it, and this migration seeds none.
    pass
