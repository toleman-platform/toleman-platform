"""Credential for authenticated active API scanning (#470)

Active scanning was anonymous, so every authenticated route answered 401
and the scan reported success anyway. These two columns let a target carry
the credential the scanner presents.

The header NAME is stored in the clear: it is not a secret, and the UI
needs to show what is configured without decrypting anything. The VALUE is
a Fernet ciphertext produced by core.crypto.encrypt_secret, the same
treatment githubappconfig.private_key_pem and githubtoken.token_ciphertext
already get -- which also means it is unreadable if PLATFORM_ENCRYPTION_KEY
is rotated or lost, exactly like those, and the operator re-enters it.

Both nullable with no default: a target without a credential keeps
scanning anonymously, which is the existing behaviour.

Revision ID: d5b28e6c1a94
Revises: c3f9a1b47d08
"""
import sqlalchemy as sa
from alembic import op

revision = "d5b28e6c1a94"
down_revision = "c3f9a1b47d08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("target", sa.Column("api_auth_header_name", sa.String(), nullable=True))
    op.add_column("target", sa.Column("api_auth_header_value_ciphertext", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("target", "api_auth_header_value_ciphertext")
    op.drop_column("target", "api_auth_header_name")
