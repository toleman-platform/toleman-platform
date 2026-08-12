from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import Target, Workspace

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("")
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()


@router.post("")
def create_target(target: Target, session: Session = Depends(get_session)):
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session)):
    return session.get(Target, target_id)
