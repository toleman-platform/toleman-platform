from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.github import github_get, repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.core import target_lifecycle
from app.models.models import PRGuardrailScan, Target

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


# How many pull requests one PR-History fetch pulls from GitHub. GitHub's own
# ceiling for a single page; taken in full because the list is then paged
# client-side at up to 100 rows, and a smaller fetch would make the pager lie
# about how much there is.
PR_LIST_PAGE_SIZE = 100

# What each dashboard PR-state choice asks GitHub for. GitHub has no "merged"
# state -- a merged PR is a closed one carrying merged_at -- so Merged and
# Closed both fetch the closed set and are split apart afterwards
# (_matches_state below).
_GITHUB_PR_STATE = {"open": "open", "closed": "closed", "merged": "closed", "all": "all"}


def _pr_state(pr: dict) -> str:
    """A PR's state as the dashboard means it. GitHub reports only open/closed;
    merged and closed-without-merging are different outcomes to a reviewer, and
    the PR-state filter offers them as separate choices. Derived here rather
    than in the client so every consumer agrees on what a PR's state is."""
    return "merged" if pr.get("merged_at") else pr["state"]


def _matches_state(pr: dict, state: str) -> bool:
    return state == "all" or _pr_state(pr) == state


def _latest_guardrail_scans(
    session: Session, target_id: int, pr_numbers: list[int]
) -> dict[int, PRGuardrailScan]:
    """Most recent PRGuardrailScan per PR number, for the PRs being rendered.

    A PR that is pushed to repeatedly accumulates one scan row per push, and
    only the newest one describes the code a reviewer is being asked to merge
    today. Ordered ascending and overwritten as we go so the last write per
    pr_number is the newest.

    Restricted to `pr_numbers` rather than the target's whole scan history: a
    target with webhook scanning on writes a row per push, so after a few
    months "every scan for this target" is tens of thousands of rows loaded
    and discarded on every request to a page the dashboard polls.
    """
    if not pr_numbers:
        return {}
    rows = session.exec(
        select(PRGuardrailScan)
        .where(
            PRGuardrailScan.target_id == target_id,
            PRGuardrailScan.pr_number.in_(pr_numbers),  # type: ignore[attr-defined]
        )
        .order_by(PRGuardrailScan.created_at, PRGuardrailScan.id)
    ).all()
    return {row.pr_number: row for row in rows}


@router.get("/prs/{target_id}")
def repo_prs(target_id: int, state: str = "open", session: Session = Depends(get_session)):
    """Pull requests on a target repo, real GitHub API data, joined to this
    target's own PR Guardrail scan history.

    `state` ("open"/"closed"/"merged"/"all") is answered by GitHub, not by
    filtering a fixed page of PRs afterwards. That distinction is the whole
    point: GitHub returns PRs newest-created first, so on a repo that closes
    PRs faster than a page of them is opened -- pallets/flask has zero open
    PRs in its 100 most recently created -- a page fetched with state=all and
    then narrowed to open in the client is empty, and the dashboard reports
    "no open pull requests" on a repo that has plenty. Merged and Closed both
    fetch GitHub's closed set (there is no merged state upstream) and are
    split by merged_at; that pair is therefore still capped at whatever share
    of the newest 100 closed PRs merged.

    `scan_status` used to be the hardcoded string "not scanned" for every PR,
    a placeholder from before PR Guardrail existed: the row said "not scanned"
    even on a PR this platform had scanned and blocked. It now reports the
    latest PRGuardrailScan for the PR, along with the id and counts the PR
    History page needs to expand a row into the vulnerabilities that scan
    found. PRs with no scan still report "not scanned" -- that is now a fact
    rather than a placeholder.
    """
    if state not in _GITHUB_PR_STATE:
        raise HTTPException(
            status_code=400,
            detail=f"state must be one of {', '.join(sorted(_GITHUB_PR_STATE))}",
        )
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)
    res = github_get(
        f"/repos/{slug}/pulls",
        params={"state": _GITHUB_PR_STATE[state], "per_page": PR_LIST_PAGE_SIZE},
        token=resolve_github_token(session, target.workspace_id, slug) or "",
    )
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail=res.text[:300])
    prs = [p for p in res.json() if _matches_state(p, state)]
    latest_scans = _latest_guardrail_scans(session, target.id, [p["number"] for p in prs])
    return [
        {
            "number": p["number"],
            "title": p["title"],
            "author": p["user"]["login"] if p.get("user") else "unknown",
            "state": _pr_state(p),
            "created_at": p["created_at"],
            "merged_at": p.get("merged_at"),
            "url": p["html_url"],
            "scan_status": scan.status if scan else "not scanned",
            "latest_scan_id": scan.id if scan else None,
            "new_findings_count": scan.new_findings_count if scan else 0,
            "highest_new_severity": scan.highest_new_severity if scan else None,
        }
        for p, scan in ((p, latest_scans.get(p["number"])) for p in prs)
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
    # (#273) Live targets only: this makes a real GitHub API call per target,
    # and a deleted one is both a wasted call and a repo that shouldn't be
    # appearing in an org activity feed at all.
    query = target_lifecycle.live_targets(select(Target))
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
