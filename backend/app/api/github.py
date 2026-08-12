from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.api.deps import get_session
from app.core.github import github_get, repo_slug_from_url
from app.models.models import Target

router = APIRouter(prefix="/api/github", tags=["github"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.get("/activity/{target_id}")
def repo_activity(target_id: int, session: Session = Depends(get_session)):
    """Recent commit activity on a target's default branch — real GitHub API data."""
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)
    res = github_get(f"/repos/{slug}/commits", params={"sha": target.default_branch, "per_page": 20})
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail=res.text[:300])
    commits = res.json()
    return [
        {
            "sha": c["sha"][:7],
            "message": c["commit"]["message"].split("\n")[0],
            "author": (c["commit"]["author"] or {}).get("name", "unknown"),
            "date": (c["commit"]["author"] or {}).get("date"),
            "url": c["html_url"],
        }
        for c in commits
    ]


@router.get("/prs/{target_id}")
def repo_prs(target_id: int, session: Session = Depends(get_session)):
    """Recent pull requests on a target repo — real GitHub API data.

    Diff-vuln status per PR is not populated: the PR Guardrail scan-on-push
    flow (architecture doc Flow C) isn't wired up yet, only native/push scans
    of default branches are. Shown as "not scanned" rather than fabricated.
    """
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)
    res = github_get(f"/repos/{slug}/pulls", params={"state": "all", "per_page": 20})
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail=res.text[:300])
    prs = res.json()
    return [
        {
            "number": p["number"],
            "title": p["title"],
            "author": p["user"]["login"] if p.get("user") else "unknown",
            "state": p["state"],
            "created_at": p["created_at"],
            "merged_at": p.get("merged_at"),
            "url": p["html_url"],
            "scan_status": "not scanned",
        }
        for p in prs
    ]


@router.get("/org-activity")
def org_activity(session: Session = Depends(get_session)):
    """Recent commit activity across every integrated target — substitutes for a
    GitHub Org audit log, which requires an Enterprise/paid-org audit log API
    scope not available for personal accounts/repos."""
    from sqlmodel import select
    targets = session.exec(select(Target)).all()
    events = []
    for target in targets:
        slug = repo_slug_from_url(target.repo_url)
        res = github_get(f"/repos/{slug}/commits", params={"sha": target.default_branch, "per_page": 5})
        if res.status_code != 200:
            continue
        for c in res.json():
            events.append({
                "target": target.name,
                "sha": c["sha"][:7],
                "message": c["commit"]["message"].split("\n")[0],
                "author": (c["commit"]["author"] or {}).get("name", "unknown"),
                "date": (c["commit"]["author"] or {}).get("date"),
                "url": c["html_url"],
            })
    events.sort(key=lambda e: e["date"] or "", reverse=True)
    return events[:50]
