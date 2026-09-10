import logging
from datetime import timedelta

from celery import Celery
from celery.signals import worker_ready
from app.core.config import settings

logger = logging.getLogger(__name__)

# `celery -A app.tasks.celery_app worker ...` (docker-compose's celery-worker
# service, #60) only imports THIS module; none of app.main's router imports
# run in that process. Without `include=[...]` here, none of the
# @celery_app.task-decorated functions in these modules would ever be
# registered on the worker, and every .delay() from the API process would
# fail with "Received unregistered task" once it actually reached a worker.
celery_app = Celery(
    "toleman",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.pr_guardrail_tasks",
        "app.tasks.discovery_tasks",
        "app.tasks.sbom_tasks",
        "app.tasks.pipeline_tasks",
        "app.tasks.api_scan_tasks",
        "app.tasks.tool_install_tasks",
        "app.tasks.github_sync_tasks",
    ],
)
celery_app.conf.task_routes = {
    "app.tasks.scan_tasks.*": {"queue": "scans"},
    "app.tasks.pr_guardrail_tasks.*": {"queue": "scans"},
    # discovery_tasks/sbom_tasks (#59) route to the same "scans" queue,
    # docker-compose's celery-worker service only consumes `-Q scans`, and
    # these do the same class of work (clone + subprocess) as scan_tasks.
    "app.tasks.discovery_tasks.*": {"queue": "scans"},
    "app.tasks.sbom_tasks.*": {"queue": "scans"},
    # pipeline_tasks (#68): GitHub API calls, not a clone+subprocess, but
    # still belongs off the request thread and behind the same worker;
    # routed to the same queue rather than standing up a new one for a
    # single task.
    "app.tasks.pipeline_tasks.*": {"queue": "scans"},
    # api_scan_tasks (#72): a real subprocess (nuclei) invocation, same class
    # of off-request-thread work as the clone+subprocess tasks above, even
    # though it doesn't clone a repo; same queue, no new worker needed.
    "app.tasks.api_scan_tasks.*": {"queue": "scans"},
    # tool_install_tasks (#216): runs `pip install` inside this same worker
    # container, so the tool actually lands in the environment scans run
    # from; not a separate installer process. Routing matters here in a
    # way it easily doesn't get noticed: without an explicit route, Celery
    # sends an unrouted task to the default "celery" queue, which
    # docker-compose's celery-worker service never consumes (`-Q scans`
    # only). The task would sit unconsumed by any worker (not fail loudly,
    # just never start) until app.core.staleness's stale-job sweep
    # eventually reported it failed with a timeout that had nothing to do
    # with the real cause.
    "app.tasks.tool_install_tasks.*": {"queue": "scans"},
    # github_sync_tasks (#385's webhook UX work): re-runs the same
    # _sync_repos a fresh App install or the manual "Sync now" button
    # already trigger, just dispatched from the installation_repositories
    # webhook instead. Same queue, for the same reason api_scan_tasks is:
    # off the request thread, behind the one worker this deployment runs.
    "app.tasks.github_sync_tasks.*": {"queue": "scans"},
}

# task_acks_late + reject_on_worker_lost: if a worker dies mid-scan (OOM, pod
# eviction, deploy) the task is redelivered to another worker instead of being
# silently dropped; pairs with run_scan's per-task autoretry_for/backoff so a
# transient failure (worker loss or clone/network error) gets a real second
# chance instead of leaving the scan stuck in "running" forever.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True

# Refreshes every target's default-branch baseline daily (app.tasks.scan_tasks
# .run_scheduled_full_scans) so PR Guardrail always has something real to diff
# against (GH-07) instead of relying on someone having clicked Scan manually,
# and so posture pages don't quietly go stale between manual runs. Requires
# `celery -A app.tasks.celery_app beat` (or `worker -B`, see docker-compose.yml's
# celery-worker command) actually running somewhere; a worker with no beat
# process never fires entries in this schedule, it just sits registered and
# unused.
celery_app.conf.beat_schedule = {
    "run-scheduled-full-scans": {
        "task": "app.tasks.scan_tasks.run_scheduled_full_scans",
        "schedule": timedelta(hours=24),
    },
    # (#385's webhook UX work, revised) The installation_repositories webhook
    # event was meant to be the only trigger for this -- a repo added to an
    # already-installed App, via GitHub's own "Configure" screen, getting a
    # Target the moment access changes. In practice that event turned out to
    # be unreliable to actually get delivered: it did not appear as a
    # selectable option on this App's own "Permissions & events" settings
    # page even after granting every permission GitHub's docs say it
    # requires (Issues, for issue_comment, was confirmed fixable the same
    # way; installation_repositories was not), and GitHub's own community
    # forum has open reports of this exact event misbehaving. Rather than
    # leave repo-sync depending on a webhook subscription this deployment
    # cannot reliably configure, this periodic poll is the guarantee: every
    # newly-granted repo gets a Target within 24h regardless of whether the
    # webhook event ever fires. The webhook handler (app/api/webhooks.py)
    # stays in place too -- if it does fire somewhere, that installation
    # gets the near-real-time behavior for free; this schedule is the floor
    # every installation gets either way.
    "sync-github-repos": {
        "task": "app.tasks.github_sync_tasks.sync_repos_task",
        "schedule": timedelta(hours=24),
    },
}


@worker_ready.connect
def _queue_missing_baseline_scans(**kwargs):
    """Beat records a fresh timedelta schedule's creation time as its last
    run and only fires once a full interval has elapsed *after that* -- it
    does not treat the first tick as immediately due. So the 24h entry
    above alone leaves any target with no baseline yet (GH-07) stuck that
    way for up to 24h after every deploy that (re)starts Beat, not
    "shortly", regardless of PR activity against it in the meantime.
    worker_ready fires once when this process finishes bootstrapping and is
    genuinely ready to accept tasks; queuing the catch-up pass here (scoped
    to targets that still have zero completed scans, see
    queue_full_scan_for_targets_missing_a_baseline's docstring) closes that
    gap without waiting on Beat's own timing, and is a no-op on any restart
    where nothing is actually missing a baseline.

    Imported lazily: scan_tasks imports celery_app at module level, so a
    top-level import back here would be circular.
    """
    from sqlmodel import Session
    from app.core.db import engine
    from app.tasks.scan_tasks import queue_full_scan_for_targets_missing_a_baseline

    try:
        with Session(engine) as session:
            queue_full_scan_for_targets_missing_a_baseline(session)
    except Exception:
        logger.exception("baseline catch-up pass failed on worker startup")

    # Same first-tick gap as above, for sync-github-repos: a fresh deploy
    # would otherwise wait up to 24h for the first repo-sync pass. Not
    # scoped like the baseline catch-up above (nothing to scope it by --
    # _sync_repos itself is already a no-op for every repo already
    # tracked), so this is just "run it now too."
    try:
        from app.tasks.github_sync_tasks import sync_repos_task

        sync_repos_task()
    except Exception:
        logger.exception("repo-sync catch-up pass failed on worker startup")
