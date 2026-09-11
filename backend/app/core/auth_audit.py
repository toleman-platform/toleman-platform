"""Security-relevant account activity logging: login/logout, password
changes, and permission changes (global role, workspace role). Separate
from app.core.triage's FindingStateLog logging -- that's the vulnerability-
posture audit trail every authenticated user can read; this is the access-
control audit trail, admin-only (see AuthAuditLog's own docstring in
app.models.models).

A single write-path function rather than each call site constructing
AuthAuditLog rows directly, so every event carries the same target_email
default and none of the seven call sites (login success/failure, logout,
password change, role change, workspace role change/removal) can drift on
that.
"""
from sqlmodel import Session

from app.models.models import AuthAuditLog, AuthEventType


def log_auth_event(
    session: Session,
    event_type: AuthEventType,
    actor: str,
    target_email: str = "",
    detail: str = "",
    ip_address: str = "",
) -> None:
    """Writes and commits immediately, same as FindingStateLog's own
    call sites: a security audit row is part of the action it records, not
    an optional side effect to batch or best-effort away. `target_email`
    defaults to `actor` (the common case: every self-service event -- login,
    logout, password change -- is about the person performing it); pass it
    explicitly for admin-on-someone-else actions (role changes)."""
    session.add(
        AuthAuditLog(
            event_type=event_type,
            actor=actor,
            target_email=target_email or actor,
            detail=detail,
            ip_address=ip_address,
        )
    )
    session.commit()
