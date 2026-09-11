"""MCP/public-API action logging (issue #108 follow-up): who (which
Toleman user, via which token) and what agent software did what, over
`/api/public/v1/*` -- the Toleman MCP server's own surface, and the same
one any other API-token integration reaches. Separate from
app.core.auth_audit's access-control trail (login/role changes) and
app.core.triage's FindingStateLog (state transitions humans make in the
UI) -- this is specifically "an API token was used to do X".

Single write-path function, one explicit call site per public_api.py
endpoint, same convention as app.core.auth_audit.log_auth_event.
"""
from sqlmodel import Session

from app.models.models import McpAuditLog, User


def log_mcp_action(
    session: Session,
    user: User,
    *,
    agent: str,
    tool: str,
    summary: str = "",
    target_id: int | None = None,
    finding_id: int | None = None,
    success: bool = True,
    error: str = "",
) -> None:
    """Writes and commits immediately -- an audit row is part of the
    action it records, not an optional side effect to batch or best-effort
    away (same reasoning as log_auth_event). Call this for both a
    successful action and one that failed for a reason worth recording
    (e.g. AutofixError opening a PR): pass success=False, error=str(exc)
    for the latter rather than skipping the log entirely, since "someone's
    token tried to do X and it failed" is itself real audit signal.

    Every public_api.py call site calls this last, right before returning
    its own response -- often the same ORM object(s) (a Target, a list of
    Finding rows, ...) the endpoint fetched earlier and is about to hand
    straight to FastAPI to serialize. commit() below expires every object
    still attached to `session`, and unlike plain `obj.attr` access in
    Python, FastAPI/pydantic-core's fast path for a SQLModel table object
    reads its __dict__ directly rather than going through SQLAlchemy's
    attribute descriptors -- so an expired-but-still-attached object
    serializes as `{}`, not a fresh reload. expunge_all() first detaches
    everything already loaded (freezing its current, already-populated
    __dict__ against this commit) before this function adds and commits
    its own new row; safe here specifically because every call site is
    the last thing that touches `session` before returning.

    `user.id` is read into a plain local *before* expunging: whether it's
    still in `user.__dict__` at this point depends on whether something
    earlier in the request happened to touch it again after
    current_api_token_user's own commit expired it (accessing an expired
    attribute on a still-attached instance transparently reloads it,
    which is why this doesn't fail every time) -- not worth depending on
    on a call site newly added here re-triggering that as a side effect."""
    user_id = user.id
    session.expunge_all()
    session.add(
        McpAuditLog(
            user_id=user_id,
            agent=agent or "unknown",
            tool=tool,
            summary=summary,
            target_id=target_id,
            finding_id=finding_id,
            success=success,
            error=error,
        )
    )
    session.commit()
