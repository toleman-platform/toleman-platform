"""Admin-only security audit log: who logged in/out (and from where), who
changed their password, and who changed whose permissions
(app.models.models.AuthAuditLog, written by app.core.auth_audit).

A separate router from app/api/audit.py's findings-oriented feed
(mounted under login_required in app/main.py -- any authenticated user can
see triage history) since this exposes login activity and permission
changes for every user on the platform, a different sensitivity level;
mounted under admin_required instead, the same gate app/api/admin.py's own
user management already uses.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, func, or_, select

from app.api.deps import get_session
from app.models.models import AuthAuditLog, AuthEventType

router = APIRouter(prefix="/api/audit", tags=["audit"])

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200


class AuthAuditLogOut(BaseModel):
    id: int
    event_type: AuthEventType
    actor: str
    target_email: str
    detail: str
    ip_address: str
    created_at: str


class SecurityAuditLogResponse(BaseModel):
    items: list[AuthAuditLogOut]
    total: int


def _out(entry: AuthAuditLog) -> AuthAuditLogOut:
    return AuthAuditLogOut(
        id=entry.id,
        event_type=entry.event_type,
        actor=entry.actor,
        target_email=entry.target_email,
        detail=entry.detail,
        ip_address=entry.ip_address,
        created_at=entry.created_at.isoformat() + "Z",
    )


@router.get("/security-log", response_model=SecurityAuditLogResponse)
def security_audit_log(
    event_type: AuthEventType | None = None,
    # Matches either actor or target_email: an admin looking up "what
    # happened around user X" wants both "X logged in" and "an admin
    # changed X's role", not just rows where X was the one who acted.
    email: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
):
    query = select(AuthAuditLog)
    if event_type is not None:
        query = query.where(AuthAuditLog.event_type == event_type)
    if email:
        query = query.where(or_(AuthAuditLog.actor == email, AuthAuditLog.target_email == email))

    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    page = max(page, 1)
    page_size = max(min(page_size, MAX_PAGE_SIZE), 1)
    items = session.exec(
        query.order_by(AuthAuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return SecurityAuditLogResponse(items=[_out(i) for i in items], total=total)


@router.get("/security-log/actors", response_model=list[str])
def security_audit_actors(session: Session = Depends(get_session)):
    """Distinct emails across both actor and target_email, for populating a
    filter dropdown -- same pattern as GET /api/audit/actors
    (app/api/audit.py's list_actors) for the findings audit feed."""
    actors = set(session.exec(select(AuthAuditLog.actor).distinct()).all())
    targets = set(session.exec(select(AuthAuditLog.target_email).distinct()).all())
    return sorted((actors | targets) - {""})
