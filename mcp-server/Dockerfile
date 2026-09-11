# Toleman MCP server, streamable-http mode: a persistent network service
# any MCP client can connect to directly (see README.md's "Remote
# (streamable-http)" section and server.py's module docstring for why this
# is a separate image from backend/Dockerfile -- a real dependency conflict
# between the `mcp` package and the backend's pinned FastAPI/SQLModel
# versions, not a build-organization choice).
#
# Pinned to the same Python 3.12 as backend/Dockerfile for consistency, even
# though this image has none of that image's wheel-compatibility
# constraints (no pydantic-core/psycopg here).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY server.py .

# Non-root runtime user, same reasoning as backend/Dockerfile: this process
# talks to the outside world (a network-facing MCP transport) and to
# Toleman's own API on every tool call, no reason to run any of that as
# root.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin toleman
USER toleman

ENV TOLEMAN_MCP_TRANSPORT=streamable-http \
    TOLEMAN_MCP_HOST=0.0.0.0 \
    TOLEMAN_MCP_PORT=8080

EXPOSE 8080

# A plain TCP connect rather than an HTTP status check: the `mcp` package's
# own streamable-http endpoint returns 406 for anything that isn't a real
# MCP session handshake (verified against a live server during
# development), so a status-code-based check would need to special-case
# that instead of treating it as unhealthy. A liveness check only needs to
# prove the process is up and accepting connections on its configured port
# (TOLEMAN_MCP_PORT, read the same way the server itself binds it), not
# replicate MCP protocol semantics.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, socket; socket.create_connection(('localhost', int(os.environ.get('TOLEMAN_MCP_PORT', 8080))), timeout=3)" || exit 1

CMD ["python", "server.py"]
