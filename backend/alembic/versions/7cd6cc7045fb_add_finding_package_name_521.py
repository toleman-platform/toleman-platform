"""Package name on finding (#521)

Trivy always names the exact package it flagged a CVE against
(parsers.py's PkgName), but that name only ever lived transiently in the
parsed item dict -- used to compute dedup_hash and then discarded.
Nothing downstream could ask "which package is this finding actually
about" once ingestion finished.

That mattered once the Fix Plan tab (app.core.remediation) started
reading OSV's own package attribution: a CVE-ID-keyed OSV lookup often
resolves to an NVD-auto-converted record with a real fixed version but
no package name at all (native GHSA/PYSEC records normally carry one;
the auto-converted ones frequently don't). Those findings were silently
dropped from every plan, no matter how many CVEs got enriched. This
column gives remediation a `fallback_package` to attribute the fix to
instead -- the same package trivy already said it was, not a guess.

Nullable, no backfill: every existing row stays NULL until its next scan
re-observes it (app.core.ingestion now sets this on the rescan path,
not just at creation), same convergence the CVE-enrichment warm-up
already relies on. No index: this column is read by CVE id via the
finding it's attached to, never filtered or searched on directly.

Revision ID: 7cd6cc7045fb
Revises: f589f48b137b
"""
import sqlalchemy as sa
from alembic import op

revision = "7cd6cc7045fb"
down_revision = "f589f48b137b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("finding", sa.Column("package_name", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("finding", "package_name")
