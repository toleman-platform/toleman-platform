from fastapi import APIRouter, Depends
from sqlmodel import Session, or_, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.core import target_lifecycle
from app.models.models import Finding, Target, User

router = APIRouter(prefix="/api/search", tags=["search"])

RESULT_LIMIT = 10


@router.get("")
def search(q: str = "", session: Session = Depends(get_session), user: User = Depends(current_user)):
    query = q.strip()
    if not query:
        return {"findings": [], "targets": []}

    like = f"%{query}%"
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"findings": [], "targets": []}

    findings_query = (
        select(Finding)
        .where(
            or_(
                Finding.title.ilike(like),
                Finding.file_path.ilike(like),
                Finding.rule_id.ilike(like),
                Finding.cve_id.ilike(like),
            )
        )
        .order_by(Finding.priority_score.desc())
        .limit(RESULT_LIMIT)
    )
    if ws_ids is not None:
        findings_query = findings_query.join(Target, Target.id == Finding.target_id).where(
            Target.workspace_id.in_(ws_ids)
        )
    findings = session.exec(findings_query).all()

    # (#273) Global search must not be the one place a deleted target is
    # still reachable by name -- every link it renders would 404.
    targets_query = target_lifecycle.live_targets(select(Target)).where(
        or_(Target.name.ilike(like), Target.repo_url.ilike(like))
    )
    if ws_ids is not None:
        targets_query = targets_query.where(Target.workspace_id.in_(ws_ids))
    targets = session.exec(targets_query.limit(RESULT_LIMIT)).all()

    return {"findings": findings, "targets": targets}
