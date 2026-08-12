from celery import Celery
from app.core.config import settings

celery_app = Celery("osp", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.task_routes = {"app.tasks.scan_tasks.*": {"queue": "scans"}}

# task_acks_late + reject_on_worker_lost: if a worker dies mid-scan (OOM, pod
# eviction, deploy) the task is redelivered to another worker instead of being
# silently dropped -- pairs with run_scan's per-task autoretry_for/backoff so a
# transient failure (worker loss or clone/network error) gets a real second
# chance instead of leaving the scan stuck in "running" forever.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True
