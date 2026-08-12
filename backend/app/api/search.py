from fastapi import APIRouter, Depends
from sqlmodel import Session, or_, select

from app.api.deps import get_session
from app.models.models import Finding, Target

router = APIRouter(prefix="/api/search", tags=["search"])

RESULT_LIMIT = 10


@router.get("")
def search(q: str = "", session: Session = Depends(get_session)):
    query = q.strip()
    if not query:
        return {"findings": [], "targets": []}

    like = f"%{query}%"

    findings = session.exec(
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
    ).all()

    targets = session.exec(
        select(Target)
        .where(or_(Target.name.ilike(like), Target.repo_url.ilike(like)))
        .limit(RESULT_LIMIT)
    ).all()

    return {"findings": findings, "targets": targets}
