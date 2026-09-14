"""CVSS vector decomposition on CveEnrichment (#201)

CveEnrichment has stored NVD's CVSS vector string since #71, but only the
aggregate score was ever read. These five columns hold the decomposition the
risk-scoring engine consumes: the CVSS version plus Attack Vector, Attack
Complexity, Privileges Required and User Interaction, in
app/core/cvss.py's canonical lowercase vocabulary ("network", "low",
"none", ...).

All nullable, and deliberately not backfilled in SQL. NULL means "not
established", which must never be scored as a benign value; and parsing a
CVSS vector in SQL would be a worse parser than the one in
app/core/cvss.py. app/core/cve_enrichment.py backfills each row from its
stored vector the first time it is read after this migration, which is the
only moment a row is touched anyway (the enrichment cache is never
re-fetched by design).

Revision ID: a4f1c9d80e37
Revises: c3e8b7a2d4f1
"""
import sqlalchemy as sa
from alembic import op

revision = "a4f1c9d80e37"
down_revision = "d41f8a7c2b93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cveenrichment", sa.Column("cvss_version", sa.String(), nullable=True))
    op.add_column("cveenrichment", sa.Column("cvss_attack_vector", sa.String(), nullable=True))
    op.add_column("cveenrichment", sa.Column("cvss_attack_complexity", sa.String(), nullable=True))
    op.add_column("cveenrichment", sa.Column("cvss_privileges_required", sa.String(), nullable=True))
    op.add_column("cveenrichment", sa.Column("cvss_user_interaction", sa.String(), nullable=True))
    # Indexed because the point of persisting the decomposition rather than
    # parsing it per request is to make "everything network-reachable that
    # needs no privileges" a query. The other two metrics are low-cardinality
    # and rarely the leading filter, so they stay unindexed.
    op.create_index("ix_cveenrichment_cvss_attack_vector", "cveenrichment", ["cvss_attack_vector"])
    op.create_index("ix_cveenrichment_cvss_privileges_required", "cveenrichment", ["cvss_privileges_required"])


def downgrade() -> None:
    op.drop_index("ix_cveenrichment_cvss_privileges_required", table_name="cveenrichment")
    op.drop_index("ix_cveenrichment_cvss_attack_vector", table_name="cveenrichment")
    op.drop_column("cveenrichment", "cvss_user_interaction")
    op.drop_column("cveenrichment", "cvss_privileges_required")
    op.drop_column("cveenrichment", "cvss_attack_complexity")
    op.drop_column("cveenrichment", "cvss_attack_vector")
    op.drop_column("cveenrichment", "cvss_version")
