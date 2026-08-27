"""Target clone credentials for VPN/client-cert-gated hosts (#298)

Adds client_cert_ciphertext/client_key_ciphertext (encrypted at rest via
app.core.crypto, mirrors GitHubToken.token_ciphertext) and clone_proxy_url
to target, so a target on a host behind a VPN or requiring mTLS (added to
EXTRA_CLONE_HOSTS by the operator) can be cloned. All default to "" (not
nullable): the common case is a plain public github.com target that needs
none of this, and "" already means "unset" everywhere else in this model
(see is_ai_repo_signals).

Revision ID: 4d3ccef7ff1e
Revises: a7d4f2e9c1b6
"""
import sqlalchemy as sa
from alembic import op

revision = "4d3ccef7ff1e"
down_revision = "a7d4f2e9c1b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "target", sa.Column("client_cert_ciphertext", sa.String(), nullable=False, server_default="")
    )
    op.add_column(
        "target", sa.Column("client_key_ciphertext", sa.String(), nullable=False, server_default="")
    )
    op.add_column("target", sa.Column("clone_proxy_url", sa.String(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("target", "clone_proxy_url")
    op.drop_column("target", "client_key_ciphertext")
    op.drop_column("target", "client_cert_ciphertext")
