import logging
import subprocess

from sqlmodel import Session, select

from app.core.db import engine
from app.core.github import repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.core.notifications import dispatch_notification
from app.core.aibom import extract_ai_components, upsert_aibom_components
from app.core.github_dependency_graph import DependencyGraphUnavailable, fetch_dependency_graph
from app.core.osv_malware_ingestion import check_and_ingest_malware
from app.core.sbom_ingestion import upsert_components
from app.core.time import utcnow
from app.models.models import NotificationEventType, SbomComponent, SbomRun, Target
from app.scanners import runner
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Same retry rationale as app/tasks/scan_tasks.py's RETRYABLE_EXCEPTIONS:
# only a `git clone` failure whose cause looks transient (network/remote
# issue) is worth retrying. RepoCloneError, bad repo_url/branch, or a
# permanent remote failure classified by runner._classify_clone_stderr
# (missing credentials, deleted repo, nonexistent branch, access denied);
# and anything else are deterministic and will fail identically on retry.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


def _notify_scan_failure(session: Session, target: Target, tool: str, error: str) -> None:
    """Issue #73 scan_failure trigger; see app.tasks.scan_tasks for the
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
    /api/sbom/{target_id} handler (#59): import the target's GitHub
    Dependency Graph, clone the default branch for the AIBOM pass, upsert the
    components, and update the SbomRun row the endpoint already created so
    GET /api/sbom/{target_id}/runs/{run_id} can report completion.

    The dependency graph is required for the *inventory*, not best-effort. It
    was best-effort while trivy was the second source and could carry a run
    on its own; with trivy's SBOM path removed it is the only source of a
    dependency inventory, so a run that cannot read it produced no inventory
    and is reported failed rather than completed-with-nothing. That
    distinction is the whole point of the sources_run/sources_failed pair: an
    empty inventory because GitHub refused to answer must never look like an
    empty inventory because the repo has no dependencies.

    It is fetched *before* the clone because it needs no checkout, so the
    failure is known and recorded early. It does not, however, short-circuit
    the rest of the run. The AIBOM pass (#190) is regexes over checked-out
    source and does not read the inventory at all, and the malware check
    (#181) runs over whatever rows are already persisted (an earlier run, or
    an upload). A repo whose dependency graph is disabled -- the default for
    private repos -- would otherwise silently lose its AI-component
    inventory entirely, which is a bigger loss than the one clone that
    skipping them saves. So the run still clones, still extracts, still
    checks; only its final status reflects that no inventory source
    succeeded.
    """
    with Session(engine) as session:
        run = session.get(SbomRun, run_id)
        if not run:
            return {"error": "sbom run not found"}

        target = session.get(Target, target_id)
        if not target:
            run.status = "failed"
            run.error = "target not found"
            run.completed_at = utcnow()
            session.add(run)
            session.commit()
            return {"error": "target not found", "run_id": run.id}

        try:
            new_components: list = []

            # (#227, raised by @r0075h3ll) GitHub's Dependency Graph is the
            # dependency inventory source. It reports what each manifest
            # actually resolves to, including transitive dependencies that
            # appear in no manifest at all; resolution GitHub has already
            # done server-side, so this needs no checkout and executes
            # nothing. On this repo's own backend that was 22 direct pins
            # versus ~98 installed packages, the gap #239 found from the
            # other direction.
            #
            # This is the right mechanism for *target* repos specifically.
            # #239 closed the same gap for our own CI by resolving
            # requirements.txt into a venv, which deliberately does not
            # generalise: resolving a customer's manifest means running
            # `pip install` on untrusted input.
            #
            # Required, not best-effort, and explicitly recorded either way.
            # A repo whose graph is disabled (the default for private repos)
            # is not a repo with no dependencies, so the failure is written to
            # sources_failed rather than swallowed; see
            # DependencyGraphUnavailable. This runs before the clone because
            # it needs no checkout; a failure here decides the run's final
            # status (see the status branch at the end) but does not skip the
            # AIBOM and malware passes, which do not depend on it.
            sources_run: list[str] = []
            sources_failed: list[str] = []
            try:
                gh_token = resolve_github_token(session, target.workspace_id, repo_slug_from_url(target.repo_url))
                gh_components = fetch_dependency_graph(target.repo_url, gh_token)
                gh_new = upsert_components(
                    session, target_id, target.default_branch, gh_components, source="github"
                )
                new_components.extend(gh_new)
                sources_run.append("github")
            except DependencyGraphUnavailable as exc:
                logger.info(
                    "GitHub dependency graph unavailable for target %s: %s", target_id, exc
                )
                sources_failed.append(f"github ({exc})")
            except Exception:
                logger.exception("GitHub dependency graph fetch failed for target %s", target_id)
                sources_failed.append("github (unexpected error)")

            repo_path = runner.clone_repo(
                target.repo_url, target.default_branch,
                resolve_github_token(session, target.workspace_id, repo_slug_from_url(target.repo_url)) or "",
                scan_id=f"sbom-{run.id}",
            )

            # Issue #190: extract the AIBOM from the checkout. The clone above
            # happens for AIBOM extraction (regexes over source, no extra
            # tooling) and is deliberately not conditional on the dependency
            # graph having answered: the AIBOM reads source, not the
            # inventory, and a repo with no dependency graph still has AI
            # components worth inventorying. Best-effort in the other
            # direction too: an AIBOM failure must not fail an otherwise-
            # successful SBOM run.
            try:
                ai_components = extract_ai_components(repo_path)
                upsert_aibom_components(session, target_id, target.default_branch, ai_components)
            except Exception:
                logger.exception("AIBOM extraction failed for target %s", target_id)

            # Issue #181: run the OSV malicious-package check over the
            # persisted inventory. Free (no clone, no subprocess; just OSV
            # HTTP calls against rows we already have) and best-effort: a
            # malware-check failure must not fail an otherwise-successful SBOM
            # run, and its own "failed" status is never reported as clean.
            # Runs even when this run added nothing, since the rows a previous
            # run or an upload left behind are still worth re-checking against
            # a moving malicious-package set.
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

            # A run no inventory source carried produced no inventory, so it
            # is failed rather than completed-with-nothing, however well the
            # AIBOM and malware passes above went. `count` is still written
            # either way, so a caller can tell "we could not ask, here is the
            # inventory an earlier run left" from "there is nothing".
            run.count = all_count
            run.new_count = len(new_components)
            run.new_ids = ",".join(str(c.id) for c in new_components)
            run.sources_run = ",".join(sources_run)
            run.sources_failed = "; ".join(sources_failed)
            run.completed_at = utcnow()
            if sources_run:
                run.status = "completed"
            else:
                run.status = "failed"
                run.error = f"No SBOM sources succeeded: {'; '.join(sources_failed)}"
            session.add(run)
            session.commit()
            if not sources_run:
                return {"error": run.error, "run_id": run.id}
            return {"run_id": run.id, "count": all_count, "new_count": len(new_components)}
        except RETRYABLE_EXCEPTIONS:
            # Transient failure: only mark the run permanently failed once
            # retries are exhausted; otherwise let it propagate so
            # Celery's autoretry_for schedules the next attempt.
            if self.request.retries >= self.max_retries:
                run.status = "failed"
                run.error = "git clone failed after retries"
                run.completed_at = utcnow()
                session.add(run)
                session.commit()
            raise
        except Exception as exc:
            run.status = "failed"
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into run state.
            run.error = runner.clone_error_message(exc)
            run.completed_at = utcnow()
            session.add(run)
            session.commit()
            return {"error": run.error, "run_id": run.id}
