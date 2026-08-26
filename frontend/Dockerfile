# Toleman frontend image: Next.js 16 app, built for production and served with
# the standalone Node server (see next.config.ts `output: "standalone"`) so
# the runtime image doesn't need the full node_modules tree.
#
# NEXT_PUBLIC_API_URL is a *build-time* arg -- Next.js inlines
# NEXT_PUBLIC_-prefixed vars into the browser bundle at `next build` time, so
# it must be passed as a build arg (docker-compose.yml does this) and set to
# an address the browser (running on the host, not in a container) can
# actually reach, e.g. http://localhost:8000 for a locally published backend
# port. Server-side requests inside this container instead use the
# API_INTERNAL_URL runtime env var (see src/lib/api.ts) so they can reach the
# backend by its compose service name.
# Base image pinned to the Node LTS line (24.x), not Current. Snyk opened
# #238 proposing node:26.7.0-slim; measuring it with our own trivy showed the
# upgrade would have made this image worse, not better:
#
#   base               fixable CRITICAL   fixable HIGH
#   node:22-slim                     1              7
#   node:24-slim                     1              6
#   node:26.7.0-slim                 0             39
#
# 26.x is built on Debian 13 (trixie), whose util-linux stack is unpatched in
# the image (CVE-2026-53612 alone accounts for seven of those highs). Trading
# one CRITICAL for 32 extra fixable HIGHs is not an upgrade, and 26.x is not
# an LTS line -- `node:lts` still resolves to 24.x.
#
# The one remaining CRITICAL (CVE-2026-59873, tar) is in npm's bundled
# dependencies. It is reachable only by running npm against a hostile tarball;
# the runner stage below serves the pre-built standalone output and never
# invokes npm. Re-measure before bumping again rather than trusting a bot's
# version suggestion.
FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24-slim AS builder
WORKDIR /app
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Standalone output already traces the minimal node_modules subset needed at
# runtime -- .next/static and public/ are copied in separately since the
# standalone server doesn't serve them from within .next/standalone itself.
# --- Non-root runtime user -------------------------------------------------
# Previously ran as root (semgrep dockerfile.security.missing-user). The
# node:22-slim base already ships an unprivileged `node` user (uid 1000), so
# there is no useradd here -- COPY --chown just hands the traced standalone
# output to it directly, which also avoids a second full-size layer that a
# separate `RUN chown -R` would create.
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static

USER node

EXPOSE 3000

CMD ["node", "server.js"]
