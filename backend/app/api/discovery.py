from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.api.deps import get_session
from app.core.config import settings
from app.models.models import Target
from app.scanners import runner
from app.scanners.discovery import discover_endpoints

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.post("/{target_id}")
def run_discovery(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")

    repo_path = runner.clone_repo(target.repo_url, target.default_branch, settings.github_token)
    endpoints = discover_endpoints(repo_path)
    return {"target_id": target_id, "count": len(endpoints), "endpoints": endpoints}
