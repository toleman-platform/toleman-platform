"""Every registered task must route to a queue a real worker consumes.

Celery does not fail loudly when a task has no explicit route: it falls back
to the default `celery` queue, and `.delay()` returns normally because
enqueueing succeeds. The task then sits there forever, because
docker-compose's celery-worker service only consumes `-Q scans`. This is
exactly what happened to `app.tasks.tool_install_tasks` -- it was added to
Celery's `include=[...]` (so the worker can deserialize it) but not to
`task_routes` (so nothing tells the worker to actually pull it), and the
first symptom would have been an install that "runs" forever and only fails
once the stale-job sweep times it out with a message that has nothing to do
with the real cause.

This test exists so that class of mistake fails a PR instead of a live
click.
"""
from app.tasks.celery_app import celery_app

# The one queue docker-compose's celery-worker service actually consumes
# (`command: celery -A app.tasks.celery_app worker -Q scans ...`). Keep this
# in sync with docker-compose.yml if that ever changes.
CONSUMED_QUEUES = {"scans"}


def _registered_task_modules() -> set[str]:
    """Every `app.tasks.*` module Celery can deserialize, per `include=[...]`."""
    return {name for name in celery_app.conf.include if name.startswith("app.tasks.")}


def test_include_is_not_empty():
    # A regression here (an empty list) would make every task fail with
    # "Received unregistered task" the moment it reached a worker.
    assert _registered_task_modules()


def test_every_task_module_has_an_explicit_route():
    routes = celery_app.conf.task_routes
    missing = sorted(
        module
        for module in _registered_task_modules()
        if f"{module}.*" not in routes
    )
    assert not missing, (
        f"these task modules are importable by the worker but have no "
        f"task_routes entry, so .delay() would silently enqueue to the "
        f"unconsumed default queue: {missing}"
    )


def test_every_route_points_at_a_consumed_queue():
    bad = {
        pattern: route["queue"]
        for pattern, route in celery_app.conf.task_routes.items()
        if route.get("queue") not in CONSUMED_QUEUES
    }
    assert not bad, f"routed to a queue no worker consumes: {bad}"


def test_tool_install_specifically_routes_to_a_consumed_queue():
    # The concrete regression this file exists to catch (#216).
    route = celery_app.conf.task_routes.get("app.tasks.tool_install_tasks.*")
    assert route is not None, "tool_install_tasks has no task_routes entry"
    assert route["queue"] in CONSUMED_QUEUES
