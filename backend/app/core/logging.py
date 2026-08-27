"""Structured logging + request correlation for the backend (#297).

Before this, `logging.getLogger(__name__)` calls scattered across the
codebase (app/main.py, the Celery tasks, most of app/core/) had no
`basicConfig`/`dictConfig` behind them anywhere, so Python's logging module
fell back to its own "no handlers found" last resort: plain unstructured
text on stderr, no timestamps, no way to tell which HTTP request (or which
of N concurrent requests) a given log line belongs to, and no aggregator
(anything reading JSON lines, e.g. CloudWatch/Datadog/Loki) could parse it
as anything but a single opaque message field.

`configure_logging()` sets one JSON formatter on the root logger so every
`getLogger(__name__)` call in the codebase inherits it for free, and
`RequestIDMiddleware` stamps every request (and everything logged while
handling it) with a correlation id.
"""

import json
import logging
import sys
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

_logger = logging.getLogger(__name__)

# Populated by RequestIDMiddleware for the duration of one request; read by
# JsonFormatter so every log line emitted while handling a request carries
# its id without every call site having to thread it through explicitly.
# Defaults to "-" for anything logged outside a request (startup, a Celery
# task, a background thread).
_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

REQUEST_ID_HEADER = "X-Request-ID"


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, logger, message,
    request_id, and exception info when present.

    Deliberately not a dependency (python-json-logger et al.): the mapping
    is fixed and small enough that a real dependency would buy nothing.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": _request_id_var.get(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON formatter on the root logger.

    Called once at process startup (app.main's lifespan, and the Celery
    worker's own entry point) rather than at import time: importing this
    module must not have the side effect of reconfiguring logging for
    whatever imports it first (e.g. a test importing app.main), only an
    explicit call should.

    Replaces any handlers already attached to the root logger rather than
    adding to them, uvicorn's own default config (or a stale handler from
    a previous configure_logging() call, relevant for tests) would
    otherwise print every line twice.

    Also re-enables every already-created logger. This matters because
    `init_db()` (app/main.py's lifespan, every startup) runs Alembic, and
    alembic/env.py calls `logging.config.fileConfig(alembic.ini)`, whose
    *default* is `disable_existing_loggers=True`. That call doesn't just
    swap the root handler, it sets `.disabled = True` on every logger
    object that already existed at that point (this module's own logger
    included), which silently turns every `logger.info(...)`/`.exception(
    ...)` call in the whole app into a no-op for the rest of the process,
    not just alembic's own migration output. Calling this function again
    after `init_db()` (which app/main.py's lifespan does) undoes that.
    """
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    for existing_logger in logging.Logger.manager.loggerDict.values():
        if isinstance(existing_logger, logging.Logger):
            existing_logger.disabled = False


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Assign each request a correlation id, echoed back as a response
    header and available to every log line emitted while handling it; also
    the last line of defense that logs (and converts to a generic 500) any
    exception the route handlers didn't turn into an HTTPException (#297).

    Reuses an inbound X-Request-ID when present (a reverse proxy or load
    balancer in front of this service, or another internal service calling
    it, may already have minted one) rather than always generating a fresh
    one, so one id can be traced across service boundaries instead of a
    new, unrelated id appearing at each hop.

    The exception handling lives here rather than in a separate
    `@app.exception_handler(Exception)` for a specific, non-obvious reason:
    Starlette special-cases a handler registered for the bare `Exception`
    class, wiring it into `ServerErrorMiddleware`, which wraps *every* user
    middleware (added automatically, outermost in the ASGI stack) rather
    than running where `app.exception_handler`-registered handlers for a
    specific type normally run (`ExceptionMiddleware`, innermost, closer to
    the router than user middleware). By the time an unhandled exception
    reaches that handler, it has already propagated out through this
    middleware's `try/except` below, the `request_id` contextvar has
    already been reset back to "-", and there is no way left to attach the
    X-Request-ID header to the response `ServerErrorMiddleware` builds.
    Catching it here instead, before that context is torn down, is what
    keeps the error response's request_id (body and header) matching every
    other log line and response for the same request.

    HTTPException is unaffected: Starlette's ExceptionMiddleware handles it
    (and any handler explicitly registered for it or a specific status
    code) before it ever reaches this middleware, so an expected 4xx raised
    throughout the API keeps behaving exactly as before.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        token = _request_id_var.set(request_id)
        try:
            try:
                response = await call_next(request)
            except Exception:
                _logger.exception(
                    "Unhandled exception on %s %s", request.method, request.url.path
                )
                response = JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error", "request_id": request_id},
                )
        finally:
            _request_id_var.reset(token)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


def current_request_id() -> str:
    """The active request's correlation id, or "-" outside a request."""
    return _request_id_var.get()
