import logging
import subprocess

from sqlmodel import Session

from app.core.api_scan_targets import ApiScanConfigError, build_scan_headers, build_scan_urls
from app.core.async_jobs import create_running_row
from app.core.db import engine
from app.core import scan_health
from app.core.ingestion import ingest_findings
from app.core.notifications import dispatch_notification
from app.core import target_lifecycle
from app.core.scan_schedules import describe_api_scan_readiness
from app.core.time import utcnow
from app.models.models import NotificationEventType, Scan, Target
from app.scanners import parsers, runner
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Only a nuclei run that timed out (subprocess.TimeoutExpired) is worth
# retrying; the target API may just have been slow/unreachable for a
# moment. ApiScanConfigError (no api_base_url configured, or every
# discovered route resolved outside the configured host) and
# FileNotFoundError (nuclei binary missing) are deterministic and won't
# change on retry, same rationale as scan_tasks.RETRYABLE_EXCEPTIONS.
RETRYABLE_EXCEPTIONS = (subprocess.TimeoutExpired,)


def _notify_api_scan_failure(session: Session, target: Target, error: str) -> None:
    try:
        dispatch_notification(
            session,
            workspace_id=target.workspace_id,
            event_type=NotificationEventType.SCAN_FAILURE,
            subject=f"Active API scan failed: {target.name}",
            detail=error,
        )
    except Exception:
        logger.exception("scan_failure notification dispatch failed for target %s", target.id)


def queue_api_scan(session: Session, target: Target) -> int | None:
    """Dispatch one active API scan for `target`, or return None if this
    target must not be probed. The unattended counterpart to
    POST /api/api-scan/{target_id}, and the mirror of
    scan_tasks.queue_full_scan on the DAST side (issue #306).

    Every refusal below is a silent no-op rather than an exception, matching
    queue_full_scan's "workspace has nothing enabled is a legitimate state"
    behaviour: this runs from a beat tick with nobody watching, and a target
    that simply is not set up for active scanning must not fill the log with
    failures or, worse, leave a permanently-red "failed" Scan row in a
    history that will never contain anything else.

    Every refusal is decided by `describe_api_scan_readiness`, the single
    function the scheduling API also reads so the dispatcher and the UI can
    never disagree about why a schedule is inert. It enforces the same
    safety boundary the interactive route does, in the same order and for
    the same reasons:

      1. The target is deactivated or soft-deleted (#273). A schedule is not
         consent to keep scanning something somebody switched off.
      2. The workspace has turned nuclei off for the `api_scan` surface
         (#232/#75). A deactivated tool stays deactivated when a schedule is
         what is asking, not just when a person is.
      3. The target has no `api_base_url`. This is the ONLY source of a scan
         host (see Target.api_base_url's docstring and
         app.core.api_scan_targets): a schedule must never infer a host from
         repo_url or from anything else, so an unconfigured target is simply
         not scanned.
      4. Nothing resolves to a scannable URL (no endpoints discovered yet,
         or every discovered route resolved off-host). Probing zero URLs is
         not a scan; recording one would be a fabricated clean result.

    Returns the dispatched Scan id, so the caller can report honestly how
    many scans a schedule actually produced.
    """
    readiness = describe_api_scan_readiness(session, target)
    if not readiness.ready:
        logger.info(
            "scheduled API scan skipped for target %s (%s): %s",
            target.id,
            readiness.reason,
            readiness.detail,
        )
        return None

    scan = create_running_row(
        session, Scan(target_id=target.id, tool="api-scan", branch=target.default_branch, status="running")
    )
    # Same .delay() onto the same "scans" queue the interactive route uses;
    # no separate scheduled-scan queue and no new concurrency. See #229: a
    # scheduled fan-out is exactly the bulk-dispatch shape that turns into
    # false all-clears when it outruns whatever the worker can actually run.
    run_api_scan.delay(target_id=target.id, scan_id=scan.id, endpoint_ids=None)
    return scan.id


@celery_app.task(
    name="app.tasks.api_scan_tasks.run_api_scan",
    bind=True,
    autoretry_for=RETRYABLE_EXCEPTIONS,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=2,
)
def run_api_scan(self, target_id: int, scan_id: int, endpoint_ids: list[int] | None = None):
    """Issue #72: active scan (nuclei) against a target's already-discovered
    API endpoints. POST /api/api-scan/{target_id} creates the Scan row
    (tool="api-scan", status="running") so it can return the id immediately,
    then dispatches this task via .delay(), same async-job pattern as
    run_scan/run_discovery/run_sbom_generation.

    Unlike those, this never clones the repo: it builds live URLs from
    Target.api_base_url + persisted ApiEndpoint rows (app.core.api_scan_targets,
    the actual safety boundary; see that module's docstring) and probes
    them directly with nuclei. Results are ingested through the exact same
    ingest_findings() path every other scanner uses, tagged tool="api-scan",
    so they get real dedup/priority-scoring/SLA/notification treatment
    rather than a bespoke storage path.
    """
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return {"error": "scan not found"}

        target = session.get(Target, target_id)
        if not target:
            scan.status = "failed"
            session.add(scan)
            session.commit()
            return {"error": "target not found", "scan_id": scan.id}

        # (#273) Re-checked on the worker, not only at POST /api/api-scan/{id}.
        # This task sends real traffic at a real deployed host, so the window
        # between dispatch and execution is exactly where a deactivation has
        # to be honoured -- "I turned this off" must stop the probe that
        # hasn't started yet, not just the next one someone asks for.
        refusal = target_lifecycle.scan_refusal_reason(target)
        if refusal:
            scan.status = "failed"
            scan.error = refusal
            scan.completed_at = utcnow()
            session.add(scan)
            session.commit()
            logger.info("api scan refused for target %s: %s", target_id, refusal)
            return {"error": refusal, "scan_id": scan.id}

        try:
            scope = build_scan_urls(session, target, endpoint_ids)
            urls, endpoints = scope.urls, scope.endpoints
            if scope.skipped:
                # Logged, not swallowed: an operator watching a scan shrink
                # needs to be able to tell a working scope rule from a
                # discovery run that found nothing.
                for skip in scope.skipped:
                    logger.info(
                        "api scan skipping %s %s for target %s: %s",
                        skip.endpoint.method,
                        skip.endpoint.route,
                        target_id,
                        skip.reason,
                    )
            if not urls:
                error = "no scannable endpoints (check api_base_url and that endpoints are discovered)"
                scan.status = "failed"
                scan.error = error
                session.add(scan)
                session.commit()
                _notify_api_scan_failure(session, target, error)
                return {"error": error, "scan_id": scan.id}

            raw_results = runner.run_nuclei(urls, headers=build_scan_headers(target))
            parsed = parsers.parse_nuclei(raw_results)
            # (#229) What makes this assertion earned rather than assumed:
            # runner.run_nuclei now checks nuclei's exit code and raises
            # ToolExecutionError on anything nonzero, so a broken nuclei run
            # reaches the generic handler below and marks the Scan failed
            # instead of returning [] and being ingested as a clean sweep
            # that mitigates every open api-scan finding. Together with the
            # config/binary/timeout handlers, reaching this line means
            # nuclei ran to completion against a real endpoint list.
            #
            # Asserted rather than left as None because None means "no
            # evidence", which would stop a legitimately clean DAST run from
            # ever clearing a finding that really was fixed.
            count = ingest_findings(
                session, target, scan,
                tool="api-scan", branch=target.default_branch, parsed=parsed,
                health=scan_health.trusted("api-scan"),
            )
            return {"scan_id": scan.id, "ingested": count, "endpoints_scanned": len(endpoints)}
        except RETRYABLE_EXCEPTIONS:
            if self.request.retries >= self.max_retries:
                error = "nuclei scan timed out after retries"
                scan.status = "failed"
                scan.error = error
                session.add(scan)
                session.commit()
                _notify_api_scan_failure(session, target, error)
            raise
        except (ApiScanConfigError, FileNotFoundError) as exc:
            error = (
                f"nuclei binary not found ({exc}); it is not bundled in the backend image yet"
                if isinstance(exc, FileNotFoundError)
                else str(exc)
            )
            scan.status = "failed"
            scan.error = error
            session.add(scan)
            session.commit()
            _notify_api_scan_failure(session, target, error)
            return {"error": error, "scan_id": scan.id}
        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)
            session.add(scan)
            session.commit()
            _notify_api_scan_failure(session, target, str(exc))
            return {"error": str(exc), "scan_id": scan.id}
