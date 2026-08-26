from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.github import github_get, repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.models.models import Target

router = APIRouter(prefix="/api/github", tags=["github"])

DEFAULT_PAGE_SIZE = 25


class OrgActivityEvent(BaseModel):
    target: str
    target_id: int
    sha: str
    message: str
    author: str
    date: str | None
    url: str


class OrgActivityResponse(BaseModel):
    items: list[OrgActivityEvent]
    total: int


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.get("/activity/{target_id}")
def repo_activity(target_id: int, session: Session = Depends(get_session)):
    """Recent commit activity on a target's default branch, real GitHub API data."""
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)
    res = github_get(f"/repos/{slug}/commits", params={"sha": target.default_branch, "per_page": 20}, token=resolve_github_token(session, target.workspace_id, slug) or "")
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
    """Recent pull requests on a target repo, real GitHub API data.

    Diff-vuln status per PR is not populated: the PR Guardrail scan-on-push
    flow (architecture doc Flow C) isn't wired up yet, only native/push scans
    of default branches are. Shown as "not scanned" rather than fabricated.
    """
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)
    res = github_get(f"/repos/{slug}/pulls", params={"state": "all", "per_page": 20}, token=resolve_github_token(session, target.workspace_id, slug) or "")
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
def org_activity(
    target_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
) -> OrgActivityResponse:
    """Recent commit activity across every integrated target, substitutes for a
    GitHub Org audit log, which requires an Enterprise/paid-org audit log API
    scope not available for personal accounts/repos.

    Issue #123: adds the same repo + date-range filter and real-pagination
    pattern as the Audit Log. target_id narrows the fetch to a single repo
    (fewer GitHub API calls, more commits fetched for that repo since
    there's only one); with no filter this still fetches a bounded number of
    commits per repo across every target, same trade-off the original
    unfiltered version made. date_from/date_to are passed straight through
    as GitHub's own `since`/`until` commit-search params (real filtering at
    the source, not a client-side guess), then the combined, sorted result
    is paginated in-process.
    """
    query = select(Target)
    if target_id is not None:
        query = query.where(Target.id == target_id)
    targets = session.exec(query).all()

    # Fetch more commits per repo when scoped to just one, since there's
    # only one GitHub API call to make either way.
    per_repo_limit = 100 if target_id is not None else 10

    commit_params: dict[str, str | int] = {"per_page": per_repo_limit}
    if date_from:
        commit_params["since"] = f"{date_from}T00:00:00Z"
    if date_to:
        commit_params["until"] = f"{date_to}T23:59:59Z"

    events: list[dict] = []
    for target in targets:
        slug = repo_slug_from_url(target.repo_url)
        res = github_get(f"/repos/{slug}/commits", params={**commit_params, "sha": target.default_branch}, token=resolve_github_token(session, target.workspace_id, slug) or "")
        if res.status_code != 200:
            continue
        for c in res.json():
            events.append({
                "target": target.name,
                "target_id": target.id,
                "sha": c["sha"][:7],
                "message": c["commit"]["message"].split("\n")[0],
                "author": (c["commit"]["author"] or {}).get("name", "unknown"),
                "date": (c["commit"]["author"] or {}).get("date"),
                "url": c["html_url"],
            })
    events.sort(key=lambda e: e["date"] or "", reverse=True)

    total = len(events)
    page = max(page, 1)
    page_size = max(min(page_size, 200), 1)
    start = (page - 1) * page_size
    page_items = events[start : start + page_size]

    return OrgActivityResponse(items=[OrgActivityEvent(**e) for e in page_items], total=total)
