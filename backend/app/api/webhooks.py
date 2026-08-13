"""GitHub webhook receiver — real-time PR Guardrail trigger (as opposed to
the on-demand "Scan This PR" button in app/api/pr_guardrail.py).

Unauthenticated by necessity (GitHub calls this directly, no session cookie
available) — trust is established via HMAC signature verification against
the App's webhook secret instead, same as any GitHub webhook integration.

GitHub's webhook delivery expects a fast response (~10s timeout), so the
actual scan is dispatched to Celery rather than run inline here.
"""
import hashlib
import hmac
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from sqlmodel import Session, select

from app.core.crypto import decrypt_secret
from app.core.db import engine
from app.core.github_app import resolve_config_for_installation
from app.models.models import GitHubAppConfig, GitHubInstallation, Target

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

TRIGGERING_ACTIONS = {"opened", "reopened", "synchronize"}


def _candidate_configs(session: Session, payload_installation_id: int | None) -> list[GitHubAppConfig]:
    """Which GitHubAppConfig(s) could plausibly have delivered this webhook
    (#34). Every GitHub App webhook delivery includes the firing
    installation's id in the payload -- resolve straight to that
    installation's own App config when present (correct even with multiple
    Apps/installations). Falls back to trying every configured App's secret
    when the id is missing/unresolvable, so a delivery isn't rejected just
    because we can't pin down which App it came from up front."""
    if payload_installation_id is not None:
        installation = session.exec(
            select(GitHubInstallation).where(GitHubInstallation.installation_id == payload_installation_id)
        ).first()
        if installation:
            config = resolve_config_for_installation(session, installation)
            if config:
                return [config]
    return session.exec(select(GitHubAppConfig)).all()


def _verify_signature(
    raw_body: bytes, signature_header: str | None, session: Session, payload_installation_id: int | None = None
) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    configs = _candidate_configs(session, payload_installation_id)
    if not configs:
        logger.warning("webhook: no GitHub App configured, rejecting delivery")
        return False

    for config in configs:
        if not config.webhook_secret:
            continue
        secret = decrypt_secret(config.webhook_secret)
        expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature_header):
            return True
    return False


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    raw_body = await request.body()
    # Parsing untrusted JSON is safe before signature verification (no
    # side effects, just structure) -- doing so lets us pull the firing
    # installation's id out of the payload (every App webhook delivery
    # carries one) so multi-App/multi-install signature verification (#34)
    # can go straight to the right App's secret instead of trying them all.
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    payload_installation_id = (payload.get("installation") or {}).get("id")

    with Session(engine) as session:
        if not _verify_signature(raw_body, x_hub_signature_256, session, payload_installation_id):
            raise HTTPException(status_code=401, detail="invalid webhook signature")

        if x_github_event != "pull_request":
            return {"ok": True, "skipped": f"event={x_github_event}"}

        action = payload.get("action")
        if action not in TRIGGERING_ACTIONS:
            return {"ok": True, "skipped": f"action={action}"}

        repo_clone_url = payload.get("repository", {}).get("clone_url")
        pr_number = payload.get("number")
        target = session.exec(select(Target).where(Target.repo_url == repo_clone_url)).first()
        if not target:
            logger.info("webhook: no target registered for %s, ignoring", repo_clone_url)
            return {"ok": True, "skipped": "no matching target"}

        from app.tasks.pr_guardrail_tasks import run_pr_guardrail_scan_task

        run_pr_guardrail_scan_task.delay(target.id, pr_number)
        return {"ok": True, "queued": True, "target_id": target.id, "pr_number": pr_number}
