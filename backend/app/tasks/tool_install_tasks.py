import logging

from sqlmodel import Session

from app.core.db import engine
from app.core.tool_install import perform_install
from app.models.models import ToolInstallRun
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.tool_install_tasks.run_tool_install")
def run_tool_install(run_id: int) -> dict:
    """Install a scanner into the running environment (#216).

    Deliberately not retried. Every other long task here retries transient
    subprocess failures, but re-running a package install after an unknown
    failure can leave a half-installed dependency tree in a worse state than
    the first attempt did, and the operator is sitting in front of a button
    they can press again themselves. A failure that says why beats a silent
    retry that changes the environment twice.
    """
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        if run is None:
            logger.warning("tool install run %s vanished before the task started", run_id)
            return {"run_id": run_id, "status": "missing"}

        # perform_install never raises: it records failures on the row,
        # because a task that dies leaves status="running" forever and the UI
        # spinning on it until the stale sweep catches up.
        perform_install(session, run)
        logger.info("tool install %s (%s) finished: %s", run_id, run.tool, run.status)
        return {"run_id": run_id, "tool": run.tool, "status": run.status}
