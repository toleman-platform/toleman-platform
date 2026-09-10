import logging

from sqlmodel import Session

from app.core.db import engine
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.github_sync_tasks.sync_repos_task")
def sync_repos_task() -> int:
    """Celery-task wrapper around app.api.github_app._sync_repos, dispatched
    from the `installation_repositories` webhook handler (app/api/webhooks.py)
    on the "added" action, so a repo granted to an existing installation
    (via GitHub's own "Configure" screen) gets a Target the moment access
    changes, instead of only at the App's initial install or whenever
    someone remembers the manual "Sync now" button
    (POST /api/github-app/sync, which calls the same _sync_repos).

    Imported lazily rather than at module level: app.api.github_app is a
    FastAPI router module (APIRouter, Depends, etc.), pulling in the whole
    API dependency chain into the Celery worker's import graph at startup
    for one helper function is unnecessary weight, not something this
    module needs any other part of.
    """
    from app.api.github_app import _sync_repos

    with Session(engine) as session:
        return _sync_repos(session)
