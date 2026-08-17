"""Short-TTL cache for per-tool `--version` health checks (senior-review
pass, #221).

`GET /api/tools/registry` ran a live subprocess `--version` check for every
registry entry on every request -- fine at the size the registry started at,
but the endpoint's own comment already quantified the cost: ~2.06s
parallelized, dominated by semgrep paying full Python interpreter startup.
That is paid by every admin on every load of the marketplace page, for
information that only changes when a tool is installed, removed, or
upgraded -- not on every page view.

Same Redis-first / in-process-fallback shape as app.core.rate_limit, for the
same reason: this backend can run as a single process (an in-memory cache is
enough) or as multiple worker processes (`uvicorn --workers N`, or
separately from the Celery worker that actually runs installs), and only
Redis is visible across all of them. The Celery worker process that runs a
tool install is a *different process* than the one serving this GET, so an
in-process-only cache could never be invalidated by an install completing --
this specifically has to go through the shared backend.

TTL is short (30s) rather than the minutes-scale TTL used elsewhere in this
codebase for genuinely stable data (CVE enrichment, EPSS/KEV). A stale
"not installed" for up to 30 seconds after someone else changes host state
outside this app entirely (e.g. `brew install trivy` by hand) is an
acceptable cost; the case that matters -- an install triggered *through this
UI* -- is handled correctly by invalidating on completion (`invalidate`,
called from app.core.tool_install), so the specific action a user just took
is never the one left stale.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Optional

import redis

from app.core.config import settings

TTL_SECONDS = 30
_KEY_PREFIX = "toolhealth:"

_redis_client: "redis.Redis | None | bool" = None


def _get_redis() -> "redis.Redis | None":
    """Same cached-unreachability pattern as app.core.rate_limit._get_redis:
    a connection failure is remembered for the life of the process so a down
    Redis costs one timeout, not one per request."""
    global _redis_client
    if _redis_client is None:
        try:
            client = redis.Redis.from_url(
                settings.redis_url, socket_connect_timeout=0.2, socket_timeout=0.2
            )
            client.ping()
            _redis_client = client
        except Exception:
            _redis_client = False
    return _redis_client or None


_memory_lock = threading.Lock()
# tool -> (expires_at_monotonic, health_dict)
_memory_cache: dict[str, tuple[float, dict]] = {}


def get(tool: str) -> Optional[dict]:
    """The cached health dict for `tool`, or None on a miss (expired,
    invalidated, or never checked)."""
    client = _get_redis()
    if client is not None:
        try:
            raw = client.get(f"{_KEY_PREFIX}{tool}")
            return json.loads(raw) if raw else None
        except Exception:
            pass  # fall through to the in-memory cache below

    with _memory_lock:
        entry = _memory_cache.get(tool)
        if entry is None:
            return None
        expires_at, health = entry
        if time.monotonic() >= expires_at:
            del _memory_cache[tool]
            return None
        return health


def set(tool: str, health: dict) -> None:
    client = _get_redis()
    if client is not None:
        try:
            client.setex(f"{_KEY_PREFIX}{tool}", TTL_SECONDS, json.dumps(health))
            return
        except Exception:
            pass  # fall through to the in-memory cache below

    with _memory_lock:
        _memory_cache[tool] = (time.monotonic() + TTL_SECONDS, health)


def invalidate(tool: str) -> None:
    """Drop the cached health for `tool` immediately.

    Called from app.core.tool_install once an install settles, so the exact
    action a user just took through this UI is never the one still showing
    stale data -- everything else is left to expire on its own TTL.
    """
    client = _get_redis()
    if client is not None:
        try:
            client.delete(f"{_KEY_PREFIX}{tool}")
        except Exception:
            pass

    with _memory_lock:
        _memory_cache.pop(tool, None)
