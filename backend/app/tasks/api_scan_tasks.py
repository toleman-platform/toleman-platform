import logging
import subprocess

from sqlmodel import Session

from app.core.api_scan_targets import ApiScanConfigError, build_scan_urls
from app.core.db import engine
from app.core.ingestion import ingest_findings
from app.core.notifications import dispatch_notification
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

        try:
            urls, endpoints = build_scan_urls(session, target, endpoint_ids)
            if not urls:
                scan.status = "failed"
                session.add(scan)
                session.commit()
                error = "no scannable endpoints (check api_base_url and that endpoints are discovered)"
                _notify_api_scan_failure(session, target, error)
                return {"error": error, "scan_id": scan.id}

            raw_results = runner.run_nuclei(urls)
            parsed = parsers.parse_nuclei(raw_results)
            count = ingest_findings(
                session, target, scan, tool="api-scan", branch=target.default_branch, parsed=parsed
            )
            return {"scan_id": scan.id, "ingested": count, "endpoints_scanned": len(endpoints)}
        except RETRYABLE_EXCEPTIONS:
            if self.request.retries >= self.max_retries:
                scan.status = "failed"
                session.add(scan)
                session.commit()
                _notify_api_scan_failure(session, target, "nuclei scan timed out after retries")
            raise
        except (ApiScanConfigError, FileNotFoundError) as exc:
            scan.status = "failed"
            session.add(scan)
            session.commit()
            _notify_api_scan_failure(session, target, str(exc))
            return {"error": str(exc), "scan_id": scan.id}
        except Exception as exc:
            scan.status = "failed"
            session.add(scan)
            session.commit()
            _notify_api_scan_failure(session, target, str(exc))
            return {"error": str(exc), "scan_id": scan.id}
