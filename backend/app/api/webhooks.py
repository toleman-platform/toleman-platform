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
from app.models.models import GitHubAppConfig, Target

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

TRIGGERING_ACTIONS = {"opened", "reopened", "synchronize"}


def _verify_signature(raw_body: bytes, signature_header: str | None, session: Session) -> bool:
    config = session.exec(select(GitHubAppConfig)).first()
    if not config or not config.webhook_secret:
        logger.warning("webhook: no webhook secret configured, rejecting delivery")
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    secret = decrypt_secret(config.webhook_secret)
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    raw_body = await request.body()

    with Session(engine) as session:
        if not _verify_signature(raw_body, x_hub_signature_256, session):
            raise HTTPException(status_code=401, detail="invalid webhook signature")

        if x_github_event != "pull_request":
            return {"ok": True, "skipped": f"event={x_github_event}"}

        payload = await request.json()
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
