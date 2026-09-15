# Toleman backend image: FastAPI API server AND Celery worker share this image
# (docker-compose.yml runs the same image with a different command for the
# celery-worker service). Bundles 7 of the scanner CLIs the platform wraps
# (Semgrep, Trivy, Gitleaks, gosec, Checkov, tfsec, Nuclei) so native scans
# work out of the box; see backend/app/scanners/runner.py for how they're
# invoked. Nuclei is the one exception to "scans a repo checkout": it drives
# Active API Scanning (#72) against already-discovered live endpoints
# instead, via app.scanners.runner.run_nuclei(); see app.core.tool_registry's
# #232 comment for the rest of that story.
#
# noseyparker is NOT bundled here (#385): it ships only as a GitHub release
# binary (no PyPI package), and this Dockerfile's own standard for that class
# of download (see the Gitleaks/Trivy/gosec/tfsec/Nuclei blocks below) is a
# version-pinned asset URL plus a checksum verified against that project's
# own published checksums file -- not a curl-pipe-bash installer script, and
# not a hash we computed ourselves from a single download and are calling
# "verified". noseyparker's own release-artifacts.yml workflow publishes no
# checksums file at all (checked directly, not just failed to find one), so
# that standard can't be met for it the way it was just met for tfsec.
# Bundling it anyway needs either upstream adding one, or a deliberate,
# documented decision to lower the bar for this one tool -- not something to
# decide unilaterally here.
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
ARG TFSEC_VERSION=1.28.14
# github.com/semgrep/semgrep-rules has no release tags, so the pin is a
# commit. Bump it deliberately, the way any other dependency here is
# bumped: this is the rule set that decides what a scan reports, and a
# floating ref would change findings under a running deployment with no
# commit to point at when someone asks why a result moved.
ARG SEMGREP_RULES_COMMIT=40b8c63f75dc7c22c8a77482d73bfb864b146f7e

# (BLD-04, revised) Checksums of the release *assets* downloaded below, per
# architecture, taken from each project's published checksums file for the
# tag pinned above. These replace the former installer-script checksums:
# the scripts are no longer used, so verifying them verified nothing that
# still runs. Verifying the tarball is strictly stronger; it covers the
# binary that actually ends up in the image rather than the program that
# fetched it.
ARG GITLEAKS_SHA256_AMD64=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba
ARG GITLEAKS_SHA256_ARM64=654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da
ARG TRIVY_SHA256_AMD64=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
ARG TRIVY_SHA256_ARM64=13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd
ARG GOSEC_SHA256_AMD64=d7882e505b1ff345d458bf0e893eec8019bc849f861ad73a212869540dd505ff
ARG GOSEC_SHA256_ARM64=63259681b6e4b9e7a24d4e187b485e75d3844d28d512b0c97dc831e51d374720
# From nuclei_3.11.1_checksums.txt at the v3.11.1 release tag, downloaded and
# verified against the actual asset (sha256sum) before pinning here, same as
# the other three above.
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
# From tfsec_checksums.txt at the v1.28.14 release tag; amd64 verified
# against the actual downloaded binary (sha256sum) before pinning, same as
# the other four above.
ARG TFSEC_SHA256_AMD64=a32d0799bbefababaa4fcd814da9f4d251cd932789590b99d1d5fcb89ace6f68
ARG TFSEC_SHA256_ARM64=7b872b0e8f398abebc21ab78f6c0535029ff649f0d18f0f3454a01bece3006a2

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
        amd64) GITLEAKS_ARCH=x64; GITLEAKS_SHA256="${GITLEAKS_SHA256_AMD64}" ;; \
        arm64) GITLEAKS_ARCH=arm64; GITLEAKS_SHA256="${GITLEAKS_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
# --retry-all-errors, on every scanner download below: without it the
# `--retry 5` beside it is close to decorative. curl only retries a narrow
# set of transient HTTP responses and timeouts by default; a
# connection-level failure -- exit 35 (SSL connect error), exit 7
# (connection refused), a reset mid-handshake -- is not retried at all, so
# the first blip fails the whole image build. That is not hypothetical: it
# is what broke #503's build-backend on an unrelated change, with curl
# exiting 35 fetching gosec while five retries stood by.
#
# --connect-timeout bounds the other half of the same problem: a hung
# connect has no deadline of its own here, so it can sit until the job
# timeout and produce a failure that looks like a slow runner rather than a
# network fault.
#
# This complements #466 rather than replacing it. That change made a failed
# download fail loudly instead of silently shipping an image without the
# scanner; this makes the transient case not fail at all. Both matter: the
# checksum verification below is what makes retrying safe, because a
# truncated or substituted download still has to match its pin.
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar xz -C /usr/local/bin -f /tmp/gitleaks.tar.gz gitleaks; \
    rm -f /tmp/gitleaks.tar.gz; \
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
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -o /tmp/trivy.tar.gz \
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
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -o /tmp/gosec.tar.gz \
        "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz"; \
    echo "${GOSEC_SHA256}  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar xz -C /usr/local/bin -f /tmp/gosec.tar.gz gosec; \
    rm -f /tmp/gosec.tar.gz; \
    gosec --version

# --- tfsec (Terraform IaC scanner) -----------------------------------------
# (#385) Was assigned to pr_guardrail's default tool set but never actually
# present in this image, so every scan reported it "failed to run" -- same
# gap #381 closed for checkov. Same asset-download-plus-checksum treatment
# as gitleaks/trivy/gosec above: tfsec ships a single raw binary per arch (no
# tar/zip wrapper), verified against tfsec_checksums.txt at the tag pinned
# below, the same file this repo's own release process publishes for every
# tag (fetched and verified against the real downloaded binary before
# pinning here).
#
# v1.28.14 is tfsec's last release: the project has folded into Trivy's own
# IaC scanning going forward (upstream says so on startup), so there will be
# no newer tag to bump to here. Kept bundled anyway since pr_guardrail still
# assigns it by name and a maintained, still-functional binary beats a
# permanent "failed to run".
#
# To bump (if a new release ever appears): change the ARG and take the new
# sum from
#   https://github.com/aquasecurity/tfsec/releases/download/vX.Y.Z/tfsec_checksums.txt
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) TFSEC_ARCH=amd64; TFSEC_SHA256="${TFSEC_SHA256_AMD64}" ;; \
        arm64) TFSEC_ARCH=arm64; TFSEC_SHA256="${TFSEC_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -o /usr/local/bin/tfsec \
        "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-${TFSEC_ARCH}"; \
    echo "${TFSEC_SHA256}  /usr/local/bin/tfsec" | sha256sum -c -; \
    chmod +x /usr/local/bin/tfsec; \
    tfsec --version

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
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -o -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f /tmp/nuclei.zip; \
    nuclei -version

# --- Public Semgrep registry (pruned at scan time) --------------------
# The `semgrep-registry` tool prunes this clone down to the languages and
# frameworks a target actually uses (app/scanners/rule_selector.py). With no
# clone present that tool raises ToolNotApplicable on every scan, which is
# the honest failure mode but means the registry half of SAST contributes
# nothing -- so it is baked into the image rather than left to be
# provisioned by hand.
#
# `git init` + `fetch --depth 1 <commit>` rather than `clone --branch`:
# it pins the exact commit ARG above, and it keeps a .git directory, which
# rule_selector's cache fingerprint reads (`git rev-parse HEAD`) to decide
# whether a cached pruned config is still valid. Without .git it falls back
# to stat'ing every file, which works but is slower and less exact.
#
# --filter=blob:none keeps the fetch small; the working tree is still
# checked out in full, which is what gets read.
#
# World-readable and root-owned on purpose: every scan only ever reads it,
# and nothing at runtime should be able to rewrite the rules it is judged
# against. The pruned configs built from it are written to a separate
# writable cache (runner.REGISTRY_CONFIG_CACHE_DIR).
# The fetch is retried for the same reason the curl downloads above are:
# git has no --retry of its own, so a single connection-level blip here
# fails the image build. Five attempts with a short backoff, then give up
# loudly -- an image without these rules is one where semgrep-registry
# raises ToolNotApplicable on every scan, which is honest but useless, so a
# silent partial success is not an option.
RUN set -eux; \
    git init /opt/semgrep-rules; \
    git -C /opt/semgrep-rules remote add origin https://github.com/semgrep/semgrep-rules.git; \
    for attempt in 1 2 3 4 5; do \
        if git -C /opt/semgrep-rules fetch --depth 1 --filter=blob:none origin "${SEMGREP_RULES_COMMIT}"; then \
            break; \
        fi; \
        if [ "$attempt" = 5 ]; then \
            echo "failed to fetch semgrep-rules at ${SEMGREP_RULES_COMMIT} after 5 attempts" >&2; \
            exit 1; \
        fi; \
        sleep 3; \
    done; \
    git -C /opt/semgrep-rules checkout --detach FETCH_HEAD; \
    chmod -R a+rX /opt/semgrep-rules; \
    test -d /opt/semgrep-rules/python

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
# (Pinned) semgrep was the one scanner installed without a version, so every
# image build resolved whatever was newest that day. For the primary SAST
# engine that means scan results are not reproducible: the same commit built a
# week apart could produce a different finding set, with no way to say which
# version produced a historical result.
#
# 1.136.0 is what the unpinned install actually resolved to, so the pin is
# behaviour-neutral. It is deliberately NOT the newest semgrep, and the gap is
# load-bearing: requirements.txt pins jsonschema==4.26.0, while semgrep 1.137.0
# narrowed to jsonschema~=4.20.0 and current releases ask for ~=4.25.1 --
# neither admits 4.26.0. 1.136.0 wants jsonschema~=4.6 and is the last release
# that fits. Pip was rediscovering that ceiling by backtracking through forty-odd
# semgrep versions on every single build; pinning also removes that work.
#
# So semgrep cannot move until jsonschema does. See #265.
RUN pip install --upgrade pip \
    && pip install -r requirements.txt semgrep==1.136.0 checkov==3.3.17 "setuptools>=78.1.1,<81" \
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

# (#229) Install the template set at build time -- deliberately AFTER
# `USER toleman` and the `ENV HOME=` above, not with the other scanner
# downloads.
#
# nuclei resolves its template store from $HOME and takes no directory flag
# from run_nuclei, so where it writes at build time has to be the same place
# it reads at runtime. Run as root earlier in this file it wrote into
# /root, while the app runs as toleman with HOME=/home/toleman -- the
# templates existed in the image and `nuclei_templates_present()` still
# answered False, so `-duc` was never applied and the fix was inert. Running
# it here, as the runtime user, makes the two paths the same by
# construction rather than by a variable both sides have to agree on.
#
# Why the flag matters: run_nuclei passes `-duc` (disable update check) so a
# scan can never be the process rewriting the shared template store while
# another scan reads it -- the same race that made trivy report a repo with
# five live CVEs as clean. But nuclei's fresh-install path sits behind that
# same update check, so on an image with no templates `-duc` would leave it
# with nothing to scan with: exit 0, zero findings, from a scanner that
# loaded no checks at all. `nuclei_templates_present()` withholds the flag
# in that case rather than risk it; baking the templates in is what makes
# the isolated path the normal one.
#
# `|| true` because the fetch is a network call at build time, and an image
# that can still scan (with the update check enabled) beats a failed build.
RUN set -eux; \
    nuclei -update-templates -silent || true; \
    nuclei -templates-version || true

EXPOSE 8000

# curl is installed above (needed at build time for the scanner downloads)
# and stays in the final image since this is a single-stage build, so it's
# available here for free.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
