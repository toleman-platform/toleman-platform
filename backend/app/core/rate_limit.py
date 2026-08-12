"""Fixed-window rate limiting for OSP API endpoints.

Backend: Redis-first, in-memory fallback.

Redis (REDIS_URL, already deployed for Celery in this stack) is used when
reachable so limits are enforced correctly across multiple worker processes
(e.g. `uvicorn --workers N` or gunicorn). If Redis can't be reached (down,
misconfigured, or intentionally not used for a small single-process OSS
deployment), we fall back transparently to an in-process in-memory counter.

Tradeoff of the in-memory fallback: it is per-process, so if you ever run
more than one worker process without a reachable Redis, the *effective*
limit multiplies by the number of processes (each process counts
independently). For a single-process deployment this is harmless and
requires no extra infra. Once you scale to multiple workers, point
REDIS_URL at a real Redis instance to get accurate shared limits.

This is intentionally a small hand-rolled limiter (fixed window via
Redis INCR/EXPIRE, or an equivalent in-memory sliding window) rather than a
third-party dependency like slowapi -- it needs no app-level wiring
(exception handlers, middleware) and stays entirely inside the endpoints
that use it, which keeps the change surface minimal.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

import redis
from fastapi import HTTPException

from app.core.config import settings

_redis_client: "redis.Redis | None | bool" = None


def _get_redis() -> "redis.Redis | None":
    """Return a working Redis client, or None if Redis is unreachable.

    The unreachability check is cached (as `False`) for the life of the
    process so we don't pay a connection-timeout penalty on every request
    once Redis has been observed to be down.
    """
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


_memory_lock = Lock()
_memory_hits: dict[str, deque] = defaultdict(deque)


def _check_memory(key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    now = time.monotonic()
    with _memory_lock:
        hits = _memory_hits[key]
        while hits and hits[0] <= now - window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            retry_after = max(1, int(window_seconds - (now - hits[0])) + 1)
            return False, retry_after
        hits.append(now)
        return True, 0


def _check_redis(client: "redis.Redis", key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    # Fixed window: bucket by the current window index so old buckets expire
    # on their own via Redis TTL and never need manual cleanup.
    bucket = int(time.time()) // window_seconds
    redis_key = f"ratelimit:{key}:{bucket}"
    pipe = client.pipeline()
    pipe.incr(redis_key, 1)
    pipe.expire(redis_key, window_seconds)
    count, _ = pipe.execute()
    if count > limit:
        return False, window_seconds
    return True, 0


def enforce_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    """Raise HTTP 429 if `key` has exceeded `limit` requests in `window_seconds`.

    `key` should already encode both the endpoint/action and the identity
    being limited (e.g. "login:203.0.113.5" or "scan_run:user:42") so
    different actions/identities never collide.
    """
    client = _get_redis()
    if client is not None:
        try:
            allowed, retry_after = _check_redis(client, key, limit, window_seconds)
        except Exception:
            # Redis started failing mid-flight (network blip, etc) -- degrade
            # to the in-memory counter for this request rather than 500ing.
            allowed, retry_after = _check_memory(key, limit, window_seconds)
    else:
        allowed, retry_after = _check_memory(key, limit, window_seconds)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Limit is {limit} per {window_seconds}s -- try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )


def _reset_for_tests() -> None:
    """Test-only helper: clear in-memory counters and force the in-memory
    backend (bypassing any locally-running Redis) so rate-limit tests are
    deterministic and isolated from real infra."""
    global _redis_client
    _redis_client = False
    with _memory_lock:
        _memory_hits.clear()
