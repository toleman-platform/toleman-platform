"""Real notification dispatch (issue #73), reusing #74's real Slack webhook
sender rather than reimplementing outbound delivery.

Recipient resolution: "users with this event type enabled, in the relevant
workspace" means every user holding a WorkspaceMembership in that workspace,
plus every global admin (admins bypass workspace scoping everywhere else in
this codebase -- see accessible_workspace_ids/enforce_workspace_role in
app.api.auth -- so they're included here too), filtered down to whichever of
those users has a NotificationPreference row for (event_type, channel) with
enabled=True.

Slack channel: there is exactly one Slack webhook per platform
(PlatformConfig.slack_webhook_url, #74) -- not one per user. A user "opting
in" to Slack for an event type doesn't get a private DM (that would require
real Slack OAuth/user-token infrastructure this project doesn't have); it
means they're named in the single message posted to the platform's
configured channel. If nobody has opted in for an event, or no webhook is
configured, nothing is sent -- this module never fabricates a delivery.

Email channel: there is no SMTP/email-sending infrastructure anywhere in
this codebase (checked: no smtplib/SendGrid/SES/Mailgun usage, no SMTP_*
settings in app.core.config). Building a fake email sender would violate
this project's "no mock data" rule just as much as faking scan results
would. So the `email` channel is a real, saveable preference (the row is
real, round-trips through the API) but dispatch for it is a deliberate
no-op that logs a clear "email delivery not yet implemented" line instead
of pretending to send something that goes nowhere. A real SMTP/provider
integration is future work, same shape as Jira's future "manual create
ticket" note in app.core.jira_integration.
"""

import logging

from sqlmodel import Session, select

from app.core.crypto import decrypt_secret
from app.core.slack_integration import send_slack_message
from app.models.models import (
    NotificationChannel,
    NotificationEventType,
    NotificationPreference,
    PlatformConfig,
    User,
    UserRole,
    WorkspaceMembership,
)

logger = logging.getLogger(__name__)


def _workspace_recipient_user_ids(session: Session, workspace_id: int) -> list[int]:
    member_ids = session.exec(
        select(WorkspaceMembership.user_id).where(WorkspaceMembership.workspace_id == workspace_id)
    ).all()
    admin_ids = session.exec(select(User.id).where(User.role == UserRole.ADMIN)).all()
    return list({*member_ids, *admin_ids})


def _users_opted_in(
    session: Session, user_ids: list[int], event_type: NotificationEventType, channel: NotificationChannel
) -> list[User]:
    if not user_ids:
        return []
    prefs = session.exec(
        select(NotificationPreference).where(
            NotificationPreference.user_id.in_(user_ids),
            NotificationPreference.event_type == event_type,
            NotificationPreference.channel == channel,
            NotificationPreference.enabled == True,  # noqa: E712 -- SQLModel/SQLAlchemy comparison, not a truthy check
        )
    ).all()
    if not prefs:
        return []
    opted_in_ids = {p.user_id for p in prefs}
    return session.exec(select(User).where(User.id.in_(opted_in_ids))).all()


def dispatch_notification(
    session: Session,
    *,
    workspace_id: int,
    event_type: NotificationEventType,
    subject: str,
    detail: str,
) -> None:
    """Fire a real notification for `event_type` to every user in
    `workspace_id` (plus global admins) who has opted in, on every channel
    they've enabled. Best-effort: a delivery failure on one channel/user is
    logged, never raised -- matches #74's Jira/Slack best-effort philosophy
    so a notification-delivery problem can never break ingestion, a scan
    task, or a findings GET request.
    """
    recipient_ids = _workspace_recipient_user_ids(session, workspace_id)
    if not recipient_ids:
        return

    _dispatch_slack(session, recipient_ids, event_type, subject, detail)
    _dispatch_email(session, recipient_ids, event_type, subject, detail)


def _dispatch_slack(
    session: Session,
    recipient_ids: list[int],
    event_type: NotificationEventType,
    subject: str,
    detail: str,
) -> None:
    users = _users_opted_in(session, recipient_ids, event_type, NotificationChannel.SLACK)
    if not users:
        return

    config = session.exec(select(PlatformConfig)).first()
    if not config or not config.slack_webhook_url:
        logger.info(
            "Notification event %s has %d Slack-opted-in recipient(s) but no Slack webhook is "
            "configured (Admin > Global Integrations) -- skipping.",
            event_type.value,
            len(users),
        )
        return

    mentions = ", ".join(u.name or u.email for u in users)
    text = f"*{subject}*\n{detail}\n_Notifying: {mentions}_"

    try:
        # slack_webhook_url is encrypted at rest (see app/api/config.py's
        # POST handler) -- must decrypt before use, same as its own
        # test-connection endpoint already does.
        webhook_url = decrypt_secret(config.slack_webhook_url)
        ok, result = send_slack_message(webhook_url, text)
    except Exception:
        logger.exception("Slack notification dispatch failed for event %s", event_type.value)
        return
    if not ok:
        logger.warning("Slack notification dispatch failed for event %s: %s", event_type.value, result)


def _dispatch_email(
    session: Session,
    recipient_ids: list[int],
    event_type: NotificationEventType,
    subject: str,
    detail: str,
) -> None:
    users = _users_opted_in(session, recipient_ids, event_type, NotificationChannel.EMAIL)
    if not users:
        return
    # No SMTP/email-sending infrastructure exists in this codebase (see
    # module docstring) -- log clearly rather than fabricate a send. Each
    # opted-in user is named individually so this is a real, useful signal
    # in server logs about what a future email integration needs to cover,
    # not a swallowed no-op.
    for user in users:
        logger.info(
            "Email delivery not yet implemented: would have notified %s (%s) of %s event: %s",
            user.email,
            event_type.value,
            subject,
            detail,
        )
