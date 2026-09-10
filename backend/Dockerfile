# Toleman backend image: FastAPI API server AND Celery worker share this image
# (docker-compose.yml runs the same image with a different command for the
# celery-worker service). Bundles 6 of the scanner CLIs the platform wraps
# (Semgrep, Trivy, Gitleaks, gosec, Checkov, Nuclei) so native scans work out
# of the box; see backend/app/scanners/runner.py for how they're invoked.
# Nuclei is the one exception to "scans a repo checkout": it drives Active
# API Scanning (#72) against already-discovered live endpoints instead, via
# app.scanners.runner.run_nuclei(); see app.core.tool_registry's #232
# comment for the rest of that story.
#
# tfsec and noseyparker are NOT bundled here: both ship only as a GitHub
# release binary (no PyPI package), and this Dockerfile's own standard for
# that class of download (see the Gitleaks/Trivy/gosec/Nuclei blocks below)
# is a version-pinned asset URL plus a checksum verified against that
# project's own published checksums file -- not a curl-pipe-bash installer
# script. Adding them means doing that properly, not skipping the
# verification step for two more tools; left for a follow-up with real
# checksums pinned, rather than merged half-done here.
#
# Pinned to Python 3.12 exactly: 3.9 is too old for this codebase, and 3.14
# breaks pydantic-core/psycopg wheel builds (see README "Architecture
# decisions" section). Do not bump the major.minor without re-verifying wheels
# exist for pydantic-core and psycopg[binary] on the new version.
FROM python:3.12-slim AS base

# Pinned scanner versions. gitleaks is pinned to the exact version already
# proven working in .github/workflows/self-scan.yml; keep it in sync with
# that file. All three now download their release asset directly, so none of
# them makes an api.github.com call during the build; see the Trivy block
# below for why that mattered.
ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.73.0
ARG GOSEC_VERSION=2.28.0
ARG NUCLEI_VERSION=3.11.1

# (BLD-04, revised) Checksums of the release *assets* downloaded below, per
# architecture, taken from each project's published checksums file for the
# tag pinned above. These replace the former installer-script checksums:
# the scripts are no longer used, so verifying them verified nothing that
# still runs. Verifying the tarball is strictly stronger; it covers the
# binary that actually ends up in the image rather than the program that
# fetched it.
ARG TRIVY_SHA256_AMD64=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
ARG TRIVY_SHA256_ARM64=13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd
ARG GOSEC_SHA256_AMD64=d7882e505b1ff345d458bf0e893eec8019bc849f861ad73a212869540dd505ff
ARG GOSEC_SHA256_ARM64=63259681b6e4b9e7a24d4e187b485e75d3844d28d512b0c97dc831e51d374720
# From nuclei_3.11.1_checksums.txt at the v3.11.1 release tag, downloaded and
# verified against the actual asset (sha256sum) before pinning here, same as
# the other three above.
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# git: needed at runtime by app/scanners/runner.py (clone_repo shells out to
# `git clone`). curl/tar/unzip/ca-certificates: needed here at build time to
# fetch and unpack the scanner binaries below (nuclei ships as a .zip, the
# other three as .tar.gz, hence both tar and unzip).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        tar \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Gitleaks (secrets scanner) --------------------------------------------
# Mirrors the exact release/asset pattern already proven in
# .github/workflows/self-scan.yml, generalized for both container arches.
# Architecture is detected with `dpkg --print-architecture` (always accurate
# for the image actually being built) rather than the BuildKit TARGETARCH
# arg, `docker compose build`'s default (non-buildx) builder doesn't
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
# Downloads the release asset directly, the same way Gitleaks above does,
# rather than running upstream's install.sh.
#
# BLD-04 pinned that script to a tag and checksummed it, which fixed the
# mutable-URL problem. What it could not fix is that the script resolves the
# release through an *unauthenticated* api.github.com call at build time.
# That call is rate-limited per runner IP, and when it is throttled the
# script reports `unable to find 'vX.Y.Z'`, indistinguishable from a
# deleted release, and fatal to the build. gosec below failed exactly that
# way on the first publish run, then succeeded unchanged on a re-run.
#
# A release asset URL at a version tag is immutable and needs no API call,
# so this keeps everything BLD-04 wanted (pinned version, verified checksum,
# no mutable fetch) while removing the network dependency that made image
# builds intermittently fail.
#
# To bump: change the ARG and take the new sums from
#   https://github.com/aquasecurity/trivy/releases/download/vX.Y.Z/trivy_X.Y.Z_checksums.txt
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) TRIVY_ASSET="Linux-64bit"; TRIVY_SHA256="${TRIVY_SHA256_AMD64}" ;; \
        arm64) TRIVY_ASSET="Linux-ARM64"; TRIVY_SHA256="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ASSET}.tar.gz"; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar xz -C /usr/local/bin -f /tmp/trivy.tar.gz trivy; \
    rm -f /tmp/trivy.tar.gz; \
    trivy --version

# --- gosec (Go SAST) ---------------------------------------------------
# Same treatment as trivy above, and for the same reason: this is the step
# whose api.github.com lookup was throttled and failed the first publish run
# with a message claiming the release did not exist. It did, the asset URL
# below returned 200 throughout.
#
# To bump: change the ARG and take the new sums from
#   https://github.com/securego/gosec/releases/download/vX.Y.Z/gosec_X.Y.Z_checksums.txt
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) GOSEC_ARCH=amd64; GOSEC_SHA256="${GOSEC_SHA256_AMD64}" ;; \
        arm64) GOSEC_ARCH=arm64; GOSEC_SHA256="${GOSEC_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/gosec.tar.gz \
        "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz"; \
    echo "${GOSEC_SHA256}  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar xz -C /usr/local/bin -f /tmp/gosec.tar.gz gosec; \
    rm -f /tmp/gosec.tar.gz; \
    gosec --version

# --- Nuclei (active API scanning against live endpoints, #72) -------------
# Was never bundled here even though app/scanners/runner.py has always
# shelled out to it unconditionally for Active API Scanning; every such scan
# failed with FileNotFoundError until this was added (see #373's
# api_scan_tasks.py fix, which at least started reporting that clearly
# instead of a bare "failed"). Same asset-download-plus-checksum treatment
# as gitleaks/trivy/gosec above, except nuclei ships as a .zip rather than
# a .tar.gz, and the binary sits inside it alongside README/LICENSE files,
# hence `unzip -o -j` (junk the paths, no subdirectory to worry about) rather
# than `tar xz`.
#
# To bump: change the ARG and take the new sums from
#   https://github.com/projectdiscovery/nuclei/releases/download/vX.Y.Z/nuclei_X.Y.Z_checksums.txt
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) NUCLEI_ARCH=amd64; NUCLEI_SHA256="${NUCLEI_SHA256_AMD64}" ;; \
        arm64) NUCLEI_ARCH=arm64; NUCLEI_SHA256="${NUCLEI_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -o -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f /tmp/nuclei.zip; \
    nuclei -version

# --- Python dependencies + Semgrep (SAST) -----------------------------
# Semgrep isn't in requirements.txt (it's a standalone CLI, same as the other
# three scanners); installed the same way CI installs it in
# .github/workflows/self-scan.yml (`pip install semgrep`).
#
# Installed in the SAME `pip install` invocation as requirements.txt, not a
# separate one; verified the hard way: a second, separate `pip install
# semgrep` call upgrades a transitive dependency to whatever its own
# (looser) constraint allows, silently overriding what requirements.txt
# resolved to, since pip does not reconsider already-installed packages'
# constraints across separate invocations. One combined invocation lets
# pip's resolver satisfy every constraint at once.
#
# This is exactly how starlette@0.38.6 (7 real CVEs, including an SSRF;
# #239) went unnoticed on main: fastapi==0.115.0's own upper bound silently
# capped it there no matter what was requested elsewhere. requirements.txt
# now pins fastapi>=0.133.0 (drops that upper bound) and starlette==1.6.0
# explicitly; the general lesson about combined installs still applies to
# every other transitive dependency, starlette is just the one with a name
# on it now.
#
# `setuptools<81` is load-bearing, not hygiene. Nothing here asks for
# setuptools directly, semgrep's pinned opentelemetry-instrumentation
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
# resolve was free to land anywhere below 81; observed landing on 70.3.0,
# which carries CVE-2025-47273 (HIGH, path traversal in PackageIndex).
# 78.1.1 is the real fix version and stays comfortably under the
# pkg_resources ceiling, so both constraints hold at once.
#
# One setuptools issue in the same scan, CVE-2026-59890 (MEDIUM, MANIFEST.in
# exclusion bypass via Unicode normalization), needs >=83.0.0; above the
# pkg_resources ceiling, so it stays open until that ceiling can be lifted.
# Not worked around here: forcing it past 81 would silently break semgrep,
# which is a worse outcome than one open MEDIUM with a documented reason.
# Tracked, alongside a HIGH in protobuf blocked the same way, in #265.
#
# `checkov` is pinned to an exact version, unlike bare `semgrep` above,
# because of what it costs the resolver rather than what it installs:
# checkov's own published metadata already pins almost its entire transitive
# tree exactly or to a narrow range (boto3==1.35.49, dpath==2.1.3, and
# similar for a dozen more), so an unpinned `checkov` forces pip to walk its
# release history looking for a version whose *fully-pinned* tree also
# satisfies requirements.txt and semgrep at the same time, backtracking
# through a full dependency resolve per candidate. .github/workflows/
# docker-images.yml builds this image with `--no-cache` on every PR by
# design (see that file), so this resolve is never cached and was observed
# taking 10+ minutes on an otherwise ~1-minute build. Pinning collapses it to
# one resolve. Checked against requirements.txt for conflicts before
# pinning: checkov==3.3.17's own ranges (jsonschema<5,>=4.17;
# pydantic<3,>=2; gitpython<4,>=3.1.30; pyyaml<7,>=6) all already contain
# this file's pins.
#
# To bump: pick a checkov release, diff its requires_dist (`curl -s
# https://pypi.org/pypi/checkov/<version>/json | python3 -c "import
# json,sys; print(chr(10).join(json.load(sys.stdin)['info']
# ['requires_dist']))"`) against requirements.txt's pins before landing it.
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt semgrep checkov==3.3.17 "setuptools>=78.1.1,<81" \
    && semgrep --version \
    && checkov --version

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
# HOME must be a real, writable directory rather than left at "/"; the
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
#
# site-packages and /usr/local/bin are chowned too, not just left
# root-owned: app/core/tool_install.py's one-click scanner install
# (#216) runs `pip install <package>` as this user at runtime, and its own
# docstring says installs land "into the running container's site-packages".
# Without this, pip can't write there, silently falls back to a `--user`
# install under $HOME/.local (a bare warning, not a failure), and the
# resulting console script lands in $HOME/.local/bin, which is not on PATH
# anywhere in this image. Every install then "succeeds" but
# _installed_version()'s version_cmd can never find the binary, so
# tool_install.py reports it as failed ("pip succeeded but the tool did not
# report a version when run") regardless of which package was requested.
# Chowning both paths keeps installs going to the normal, already-on-PATH
# location instead.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin toleman \
    && mkdir -p /tmp/toleman-scans /home/toleman/.cache \
    && chown -R toleman:toleman /app /tmp/toleman-scans /home/toleman \
        /usr/local/lib/python3.12/site-packages /usr/local/bin

ENV HOME=/home/toleman \
    XDG_CACHE_HOME=/home/toleman/.cache

USER toleman

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
