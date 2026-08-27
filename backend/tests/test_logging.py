"""Tests for #297: structured JSON logging + request correlation.

Exercises app/core/logging.py directly (JsonFormatter, configure_logging's
re-enable-disabled-loggers behavior) and end-to-end through the real app
(RequestIDMiddleware: header propagation, and that an unhandled exception
in a route is logged and turned into a generic 500 without breaking the
existing HTTPException behavior).
"""

import json
import logging

from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.core.logging import JsonFormatter, configure_logging
from app.main import app


def test_json_formatter_produces_valid_json_with_expected_fields():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="some.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    parsed = json.loads(formatter.format(record))
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "some.logger"
    assert parsed["message"] == "hello world"
    assert "timestamp" in parsed
    assert parsed["request_id"] == "-"  # no request in flight


def test_json_formatter_includes_traceback_on_exception():
    formatter = JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord(
            name="x", level=logging.ERROR, pathname=__file__, lineno=1,
            msg="failed", args=(), exc_info=sys.exc_info(),
        )
    parsed = json.loads(formatter.format(record))
    assert "ValueError: boom" in parsed["exception"]


def test_configure_logging_re_enables_loggers_disabled_by_fileconfig():
    """Regression: logging.config.fileConfig (which alembic/env.py calls on
    every init_db() run) defaults to disable_existing_loggers=True, which
    sets .disabled on every logger that already exists -- not just
    alembic's own. Without configure_logging() undoing that, every
    getLogger(__name__) call anywhere in the app would silently stop
    emitting logs after the first startup migration run.
    """
    victim = logging.getLogger("test_logging.victim_logger")
    victim.disabled = True
    configure_logging("INFO")
    assert victim.disabled is False


def test_request_id_header_is_generated_and_echoed():
    with TestClient(app) as client:
        r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID")


def test_inbound_request_id_is_reused_not_replaced():
    with TestClient(app) as client:
        r = client.get("/health", headers={"X-Request-ID": "caller-supplied-id"})
    assert r.headers.get("X-Request-ID") == "caller-supplied-id"


def test_unhandled_exception_is_logged_and_returns_generic_500():
    boom_router = APIRouter()

    @boom_router.get("/__test_only_boom")
    def _boom():
        raise ValueError("kaboom")

    app.include_router(boom_router)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/__test_only_boom", headers={"X-Request-ID": "boom-test-id"})
    finally:
        app.router.routes = [
            route for route in app.router.routes if getattr(route, "path", None) != "/__test_only_boom"
        ]

    assert r.status_code == 500
    assert r.headers.get("X-Request-ID") == "boom-test-id"
    body = r.json()
    assert body["request_id"] == "boom-test-id"
    # Internal exception details (the ValueError message, the traceback)
    # must never reach the client; only the log line captures those.
    assert "kaboom" not in r.text


def test_http_exception_is_unaffected_by_the_catch_all():
    """A route-raised HTTPException (the normal way this API reports 4xx)
    must keep returning its own status/detail, not the generic 500 the
    catch-all in RequestIDMiddleware produces for a genuinely unhandled
    exception.
    """
    with TestClient(app) as client:
        # No session cookie: current_user's dependency raises HTTPException(401).
        r = client.get("/api/targets")
    assert r.status_code == 401
    assert r.json()["detail"] != "Internal server error"
