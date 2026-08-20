import logging
import subprocess
from datetime import datetime

from sqlmodel import Session, select

from app.core.db import engine
from app.core.github import repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.core.notifications import dispatch_notification
from app.core.aibom import extract_ai_components, upsert_aibom_components
from app.core.github_dependency_graph import DependencyGraphUnavailable, fetch_dependency_graph
from app.core.osv_malware_ingestion import check_and_ingest_malware
from app.core.sbom_ingestion import upsert_components
from app.models.models import NotificationEventType, SbomComponent, SbomRun, Target
from app.scanners import runner
from app.scanners.parsers import parse_trivy_sbom
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Same retry rationale as app/tasks/scan_tasks.py's RETRYABLE_EXCEPTIONS:
# only a `git clone` failure whose cause looks transient (network/remote
# issue) is worth retrying. RepoCloneError -- bad repo_url/branch, or a
# permanent remote failure classified by runner._classify_clone_stderr
# (missing credentials, deleted repo, nonexistent branch, access denied) --
# and anything else are deterministic and will fail identically on retry.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


def _notify_scan_failure(session: Session, target: Target, tool: str, error: str) -> None:
    """Issue #73 scan_failure trigger -- see app.tasks.scan_tasks for the
    same helper's full rationale; SBOM generation runs are one of the three
    "Scan/DiscoveryRun/SbomRun row transitions to failed" cases the issue
    calls out."""
    try:
        dispatch_notification(
            session,
            workspace_id=target.workspace_id,
            event_type=NotificationEventType.SCAN_FAILURE,
            subject=f"SBOM generation failed: {target.name} ({tool})",
            detail=error,
        )
    except Exception:
        logger.exception("scan_failure notification dispatch failed for target %s", target.id)


@celery_app.task(
    name="app.tasks.sbom_tasks.run_sbom_generation",
    bind=True,
    autoretry_for=RETRYABLE_EXCEPTIONS,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
)
def run_sbom_generation(self, target_id: int, run_id: int):
    """Async counterpart to the previously-synchronous POST
    /api/sbom/{target_id} handler (#59): clone the target's default branch,
    run trivy's CycloneDX SBOM scan, upsert the components, and update the
    SbomRun row the endpoint already created so
    GET /api/sbom/{target_id}/runs/{run_id} can report completion.
    """
    with Session(engine) as session:
        run = session.get(SbomRun, run_id)
        if not run:
            return {"error": "sbom run not found"}

        target = session.get(Target, target_id)
        if not target:
            run.status = "failed"
            run.error = "target not found"
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"error": "target not found", "run_id": run.id}

        try:
            repo_path = runner.clone_repo(
                target.repo_url, target.default_branch,
                resolve_github_token(session, target.workspace_id, repo_slug_from_url(target.repo_url)) or "",
                scan_id=f"sbom-{run.id}",
            )
            raw = runner.run_tool("trivy-sbom", repo_path)
            discovered = parse_trivy_sbom(raw)
            new_components = upsert_components(
                session, target_id, target.default_branch, discovered, source="trivy"
            )

            # (#227, raised by @r0075h3ll) GitHub's Dependency Graph as a
            # second source. trivy reads dependency manifests and reports
            # what is pinned there; GitHub reports what those manifests
            # actually resolve to, including transitive dependencies that
            # appear in no manifest at all. On this repo's own backend that
            # was 22 direct pins versus ~98 installed packages -- the gap
            # #239 found from the other direction.
            #
            # This is the right mechanism for *target* repos specifically.
            # #239 closed the same gap for our own CI by resolving
            # requirements.txt into a venv, which deliberately does not
            # generalise: resolving a customer's manifest means running
            # `pip install` on untrusted input. GitHub has already done the
            # resolution server-side, so this needs no checkout and executes
            # nothing.
            #
            # Best-effort and explicitly recorded. A repo whose graph is
            # disabled (the default for private repos) is not a repo with no
            # dependencies, so the failure is written to sources_failed
            # rather than swallowed -- see DependencyGraphUnavailable.
            sources_run = ["trivy"]
            sources_failed: list[str] = []
            try:
                gh_components = fetch_dependency_graph(target.repo_url, settings.github_token)
                gh_new = upsert_components(
                    session, target_id, target.default_branch, gh_components, source="github"
                )
                new_components.extend(c for c in gh_new if c not in new_components)
                sources_run.append("github")
            except DependencyGraphUnavailable as exc:
                logger.info(
                    "GitHub dependency graph unavailable for target %s: %s", target_id, exc
                )
                sources_failed.append(f"github ({exc})")
            except Exception:
                logger.exception("GitHub dependency graph fetch failed for target %s", target_id)
                sources_failed.append("github (unexpected error)")

            # Issue #190: extract the AIBOM from the same checkout. Free --
            # the clone above already happened, and extraction is regexes
            # over source, no extra tooling. Best-effort: an AIBOM failure
            # must not fail an otherwise-successful SBOM run.
            try:
                ai_components = extract_ai_components(repo_path)
                upsert_aibom_components(session, target_id, target.default_branch, ai_components)
            except Exception:
                logger.exception("AIBOM extraction failed for target %s", target_id)

            # Issue #181: run the OSV malicious-package check over the freshly
            # persisted inventory. Free (no clone, no subprocess -- just OSV
            # HTTP calls against rows we already have) and best-effort: a
            # malware-check failure must not fail an otherwise-successful SBOM
            # run, and its own "failed" status is never reported as clean.
            try:
                check_and_ingest_malware(session, target)
            except Exception:
                logger.exception("Malware check failed for target %s", target_id)

            all_count = len(
                session.exec(
                    select(SbomComponent).where(
                        SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch
                    )
                ).all()
            )

            run.status = "completed"
            run.count = all_count
            run.new_count = len(new_components)
            run.new_ids = ",".join(str(c.id) for c in new_components)
            run.sources_run = ",".join(sources_run)
            run.sources_failed = "; ".join(sources_failed)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"run_id": run.id, "count": all_count, "new_count": len(new_components)}
        except RETRYABLE_EXCEPTIONS:
            # Transient failure: only mark the run permanently failed once
            # retries are exhausted -- otherwise let it propagate so
            # Celery's autoretry_for schedules the next attempt.
            if self.request.retries >= self.max_retries:
                run.status = "failed"
                run.error = "git clone failed after retries"
                run.completed_at = datetime.utcnow()
                session.add(run)
                session.commit()
            raise
        except Exception as exc:
            run.status = "failed"
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into run state.
            run.error = runner.clone_error_message(exc)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"error": run.error, "run_id": run.id}
