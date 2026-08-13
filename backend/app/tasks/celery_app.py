from celery import Celery
from app.core.config import settings

# `celery -A app.tasks.celery_app worker ...` (docker-compose's celery-worker
# service, #60) only imports THIS module -- none of app.main's router imports
# run in that process. Without `include=[...]` here, none of the
# @celery_app.task-decorated functions in these modules would ever be
# registered on the worker, and every .delay() from the API process would
# fail with "Received unregistered task" once it actually reached a worker.
celery_app = Celery(
    "osp",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.pr_guardrail_tasks",
        "app.tasks.discovery_tasks",
        "app.tasks.sbom_tasks",
    ],
)
celery_app.conf.task_routes = {
    "app.tasks.scan_tasks.*": {"queue": "scans"},
    "app.tasks.pr_guardrail_tasks.*": {"queue": "scans"},
    # discovery_tasks/sbom_tasks (#59) route to the same "scans" queue --
    # docker-compose's celery-worker service only consumes `-Q scans`, and
    # these do the same class of work (clone + subprocess) as scan_tasks.
    "app.tasks.discovery_tasks.*": {"queue": "scans"},
    "app.tasks.sbom_tasks.*": {"queue": "scans"},
}

# task_acks_late + reject_on_worker_lost: if a worker dies mid-scan (OOM, pod
# eviction, deploy) the task is redelivered to another worker instead of being
# silently dropped -- pairs with run_scan's per-task autoretry_for/backoff so a
# transient failure (worker loss or clone/network error) gets a real second
# chance instead of leaving the scan stuck in "running" forever.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True
