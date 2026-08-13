# OSP frontend image: Next.js 16 app, built for production and served with
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
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-slim AS builder
WORKDIR /app
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Standalone output already traces the minimal node_modules subset needed at
# runtime -- .next/static and public/ are copied in separately since the
# standalone server doesn't serve them from within .next/standalone itself.
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000

CMD ["node", "server.js"]
