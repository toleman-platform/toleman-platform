from celery import Celery
from app.core.config import settings

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
}

# task_acks_late + reject_on_worker_lost: if a worker dies mid-scan (OOM, pod
# eviction, deploy) the task is redelivered to another worker instead of being
# silently dropped; pairs with run_scan's per-task autoretry_for/backoff so a
# transient failure (worker loss or clone/network error) gets a real second
# chance instead of leaving the scan stuck in "running" forever.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True
