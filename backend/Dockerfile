# Toleman backend image: FastAPI API server AND Celery worker share this image
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

# (BLD-04) Checksums of the *installer scripts* fetched below, at the tags
# pinned above. Pinning the tool version never covered these -- the scripts
# were pulled from a mutable branch tip.
ARG TRIVY_INSTALLER_SHA256=e00df553be558995b994758bc8995956554a16937f456dc6615b0cc411bfec7a
ARG GOSEC_INSTALLER_SHA256=2aafc038c170fb6141727d247ad5a17ded5bf195ad0fb8ed1b8e0aed326ac78f

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
# The *tool* version was already pinned; the installer script was not -- it
# was fetched from the tip of the default branch, so a build was reproducible
# only for as long as nobody pushed to that branch (finding BLD-04). For a
# product whose pitch is supply-chain safety, its own build depending on a
# mutable URL is the first thing a reviewer points at.
#
# Two changes: fetch the script from the *same tag* as the version being
# installed, and verify its checksum before running it. The tag pin alone
# already removes the moving target; the checksum is what makes a
# force-pushed or retagged script fail the build loudly instead of silently
# executing something else.
#
# To bump: change the ARG, re-fetch the script, and record the new sum with
#   curl -sSL <url> | sha256sum
RUN curl -sSL -o /tmp/trivy-install.sh \
        "https://raw.githubusercontent.com/aquasecurity/trivy/v${TRIVY_VERSION}/contrib/install.sh" \
    && echo "${TRIVY_INSTALLER_SHA256}  /tmp/trivy-install.sh" | sha256sum -c - \
    && sh /tmp/trivy-install.sh -b /usr/local/bin "v${TRIVY_VERSION}" \
    && rm -f /tmp/trivy-install.sh \
    && trivy --version

# --- gosec (Go SAST) ---------------------------------------------------
# Same treatment as trivy above (BLD-04). Not Go-toolchain-dependent -- the
# script just downloads the prebuilt release binary.
RUN curl -sSL -o /tmp/gosec-install.sh \
        "https://raw.githubusercontent.com/securego/gosec/v${GOSEC_VERSION}/install.sh" \
    && echo "${GOSEC_INSTALLER_SHA256}  /tmp/gosec-install.sh" | sha256sum -c - \
    && sh /tmp/gosec-install.sh -b /usr/local/bin "v${GOSEC_VERSION}" \
    && rm -f /tmp/gosec-install.sh \
    && gosec --version

# --- Python dependencies + Semgrep (SAST) -----------------------------
# Semgrep isn't in requirements.txt (it's a standalone CLI, same as the other
# three scanners) -- installed the same way CI installs it in
# .github/workflows/self-scan.yml (`pip install semgrep`).
#
# Installed in the SAME `pip install` invocation as requirements.txt, not a
# separate one -- verified the hard way: a second, separate `pip install
# semgrep` call upgrades a transitive dependency to whatever its own
# (looser) constraint allows, silently overriding what requirements.txt
# resolved to, since pip does not reconsider already-installed packages'
# constraints across separate invocations. One combined invocation lets
# pip's resolver satisfy every constraint at once.
#
# This is exactly how starlette@0.38.6 (7 real CVEs, including an SSRF --
# #239) went unnoticed on main: fastapi==0.115.0's own upper bound silently
# capped it there no matter what was requested elsewhere. requirements.txt
# now pins fastapi>=0.133.0 (drops that upper bound) and starlette==1.6.0
# explicitly -- the general lesson about combined installs still applies to
# every other transitive dependency, starlette is just the one with a name
# on it now.
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
#
# The floor (#239's transitive-dependency scan job found this) matters just
# as much as the ceiling: nothing pinned a minimum, so an unconstrained
# resolve was free to land anywhere below 81 -- observed landing on 70.3.0,
# which carries CVE-2025-47273 (HIGH, path traversal in PackageIndex).
# 78.1.1 is the real fix version and stays comfortably under the
# pkg_resources ceiling, so both constraints hold at once.
#
# One setuptools issue in the same scan, CVE-2026-59890 (MEDIUM, MANIFEST.in
# exclusion bypass via Unicode normalization), needs >=83.0.0 -- above the
# pkg_resources ceiling, so it stays open until that ceiling can be lifted.
# Not worked around here: forcing it past 81 would silently break semgrep,
# which is a worse outcome than one open MEDIUM with a documented reason.
# Tracked, alongside a HIGH in protobuf blocked the same way, in #265.
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt semgrep "setuptools>=78.1.1,<81" \
    && semgrep --version

COPY . .

# (BLD-01) Build identity, surfaced by GET /health and the sidebar. Fed by
# CI from the real commit; "dev" is the honest default for a local build
# rather than a fabricated version number.
ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=""
ENV BUILD_VERSION=${BUILD_VERSION} \
    BUILD_COMMIT=${BUILD_COMMIT}

# --- Non-root runtime user -------------------------------------------------
# The image previously ran everything as root (flagged by semgrep's
# dockerfile.security.missing-user rule). Dropping privileges is not just a
# lint fix here: this container shells out to four scanner CLIs against
# arbitrary cloned third-party repositories, so a scanner parsing hostile
# input is the exact place you do not want root.
#
# HOME must be a real, writable directory rather than left at "/" -- the
# scanners keep caches under it and silently fail or re-download on every
# invocation otherwise. Concretely: trivy stores its vulnerability DB in
# $HOME/.cache/trivy (a multi-hundred-MB download it refuses to run without),
# and semgrep writes $HOME/.semgrep. XDG_CACHE_HOME is set explicitly because
# trivy honours it in preference to $HOME/.cache.
#
# The scan workdir (app/core/config.py's scan_workdir) is created and chowned
# here rather than relying on /tmp being world-writable, so the directory's
# ownership is explicit and does not depend on the umask of whoever created
# it first. A deployment that overrides SCAN_WORKDIR to somewhere outside
# /tmp must chown that path itself.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin toleman \
    && mkdir -p /tmp/toleman-scans /home/toleman/.cache \
    && chown -R toleman:toleman /app /tmp/toleman-scans /home/toleman

ENV HOME=/home/toleman \
    XDG_CACHE_HOME=/home/toleman/.cache

USER toleman

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
