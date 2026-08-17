# OSP backend image: FastAPI API server AND Celery worker share this image
# (docker-compose.yml runs the same image with a different command for the
# celery-worker service). Bundles the 4 scanner CLIs the platform wraps
# (Semgrep, Trivy, Gitleaks, gosec) so native scans work out of the box --
# see backend/app/scanners/runner.py for how they're invoked.
#
# Pinned to Python 3.12 exactly: 3.9 is too old for this codebase, and 3.14
# breaks pydantic-core/psycopg wheel builds (see README "Architecture
# decisions" section). Do not bump the major.minor without re-verifying wheels
# exist for pydantic-core and psycopg[binary] on the new version.
FROM python:3.12-slim AS base

# Pinned scanner versions. gitleaks is pinned to the exact version already
# proven working in .github/workflows/self-scan.yml -- keep it in sync with
# that file. trivy and gosec aren't installed anywhere in CI today (self-scan
# skips gosec entirely since this repo has no Go source, and uses the
# aquasecurity/trivy-action GitHub Action rather than a raw shell install for
# trivy) so those two use each project's own official install script instead,
# pinned to a specific release tag for reproducibility.
ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.73.0
ARG GOSEC_VERSION=2.28.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# git: needed at runtime by app/scanners/runner.py (clone_repo shells out to
# `git clone`). curl/tar/ca-certificates: needed here at build time to fetch
# the scanner binaries below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        tar \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Gitleaks (secrets scanner) --------------------------------------------
# Mirrors the exact release/asset pattern already proven in
# .github/workflows/self-scan.yml, generalized for both container arches.
# Architecture is detected with `dpkg --print-architecture` (always accurate
# for the image actually being built) rather than the BuildKit TARGETARCH
# arg -- `docker compose build`'s default (non-buildx) builder doesn't
# reliably populate TARGETARCH, which left it empty and broke this step.
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) GITLEAKS_ARCH=x64 ;; \
        arm64) GITLEAKS_ARCH=arm64 ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
        | tar xz -C /usr/local/bin gitleaks; \
    gitleaks version

# --- Trivy (SCA / container / filesystem scanner) --------------------------
# Official install script auto-detects OS/arch; pinned to a specific tag.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
    && trivy --version

# --- gosec (Go SAST) ---------------------------------------------------
# Official install script auto-detects OS/arch; pinned to a specific tag.
# Not Go-toolchain-dependent -- it just downloads the prebuilt release binary.
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh \
        | sh -s -- -b /usr/local/bin "v${GOSEC_VERSION}" \
    && gosec --version

# --- Python dependencies + Semgrep (SAST) -----------------------------
# Semgrep isn't in requirements.txt (it's a standalone CLI, same as the other
# three scanners) -- installed the same way CI installs it in
# .github/workflows/self-scan.yml (`pip install semgrep`).
#
# Installed in the SAME `pip install` invocation as requirements.txt, not a
# separate one -- verified the hard way: a second, separate `pip install
# semgrep` call upgrades starlette to whatever its own (looser) constraint
# allows, silently breaking fastapi==0.115.0 (pinned to
# starlette<0.39.0,>=0.37.2) with "Router.__init__() got an unexpected
# keyword argument 'on_startup'" at import time, since pip does not
# reconsider already-installed packages' constraints across separate
# invocations. One combined invocation lets pip's resolver satisfy both
# constraints at once (starlette stays at 0.38.6).
#
# `setuptools<81` is load-bearing, not hygiene. Nothing here asks for
# setuptools directly -- semgrep's pinned opentelemetry-instrumentation
# (0.46b0) declares `setuptools>=16.0`, so pip installs the newest one.
# setuptools 82.0.0 removed `pkg_resources`, which that same module imports
# at line 4 of its dependencies.py, so an unconstrained resolve builds an
# image whose `semgrep --version` dies with ModuleNotFoundError. Verified by
# bisecting real installs: pkg_resources is present in 81.0.0 and gone in
# 82.0.0.
#
# Pinned below 81 rather than below 82 because 81 still *has*
# pkg_resources but warns on every import, so a working image would print a
# deprecation notice on every semgrep invocation. Drop this pin once semgrep
# ships an opentelemetry that no longer imports pkg_resources.
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt semgrep "setuptools<81" \
    && semgrep --version

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
