"""Native execution: clone target repo, run CLI security tools, return raw output.

MVP note: runs directly via subprocess (no container isolation yet). Architecture
review flagged this as a blocker before mass-scale/multi-tenant rollout; fine for
single-user local/dev use, must move to ephemeral containers (K8s Job) before
that feature ships.
"""
import base64
import fcntl
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from app.core.config import settings
from app.core.scan_health import ScanHealth

logger = logging.getLogger(__name__)

# Hosts clone_repo will actually clone from. github.com is the only host this
# platform integrates with today (see repo_slug_from_url in app/core/github.py,
# which hardcodes the same assumption for the GitHub REST API). Anything else
# is rejected outright rather than handed to `git clone`.
ALLOWED_CLONE_HOSTS = {"github.com"}

# Curated LLM-security rules (issue #189), shipped in-repo rather than pulled
# from a registry. See the ruleset headers for why precision is prioritised
# over coverage. Resolved off __file__ so it works the same in the container
# image and a local checkout.
LLM_RULES_DIR = Path(__file__).parent / "rules" / "llm"

TOOL_COMMANDS = {
    # --disable-nosem: semgrep respects a `# nosemgrep` (or `# nosem`) trailing
    # comment by default, silently dropping that finding before it's even
    # written to stdout -- exactly the kind of source-level suppression a
    # security *scanner* can't allow, since it lets whoever can edit a file
    # (a careless commit, a compromised dependency, an overly-helpful
    # coding agent papering over a real finding instead of fixing it) blind
    # this tool to their own vulnerable line. This flag makes semgrep report
    # regardless of the comment; nothing downstream (this scanner, PR
    # Guardrail, the MCP server's check_code_for_vulnerabilities, which all
    # share this same TOOL_COMMANDS entry via run_tool) ever sees a
    # nosemgrep-suppressed line as anything but a real, reported finding.
    "semgrep": lambda path: ["semgrep", "scan", "--config=auto", "--disable-nosem", "--json", "--quiet", path],
    # Issue #189: the LLM ruleset runs as its own tool rather than as an extra
    # --config on the semgrep entry above. Findings then carry tool
    # "semgrep-llm", so per-tool coverage reporting, usage assignment (#75)
    # and triage can all distinguish "the registry's generic rules" from
    # "Toleman's LLM rules" instead of merging them into one bucket. Same
    # reasoning as trivy vs trivy-license already being separate entries.
    "semgrep-llm": lambda path: [
        "semgrep", "scan", f"--config={LLM_RULES_DIR}", "--disable-nosem", "--json", "--quiet", path
    ],
    # `--report-path` was /dev/stdout until #253. That is not portable: where
    # /dev/stdout isn't writable by the process, gitleaks aborts with
    # "Report path is not writable" *before scanning anything*, exits 1 and
    # writes nothing; which used to read as "no secrets found". The exit
    # code is now checked, and the report goes to a real temp file so the
    # failure doesn't happen in the first place. Same treatment as modelscan.
    # noseyparker (#255). Two-step by design: `scan` writes into a datastore,
    # `report` renders it. run_tool substitutes a real temp datastore for the
    # placeholder, same pattern as modelscan's report file.
    "noseyparker": lambda path: ["noseyparker", "scan", "--datastore", NOSEYPARKER_DATASTORE_PLACEHOLDER, path],
    "gitleaks": lambda path: ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", GITLEAKS_REPORT_PLACEHOLDER, "--no-git", "--exit-code", "0"],
    # `--scanners vuln` (issue #244 benchmarking, 2026-08-22): trivy's default
    # scanner set is [vuln, secret], not [vuln, misconfig] -- misconfig has
    # never actually run here, since enabling it needs an explicit
    # `--scanners misconfig`/`misconfig,vuln` this entry never passed.
    # parsers.parse_trivy reads Vulnerabilities and Misconfigurations from the
    # JSON, never Secrets -- so the secret scanner has been walking every file
    # on every invocation and its result was discarded unused (gitleaks
    # already covers secrets in this pipeline). Measured: 32.9s -> 1.5s on a
    # venv-inclusive checkout, 13.3s -> 3.8s on a real multi-ecosystem repo
    # (getsentry/sentry), identical Vulnerabilities output both times --
    # Misconfigurations was empty before and stays empty after, since that
    # scanner still isn't enabled. Zero behavior change to parsed findings.
    "trivy": lambda path: ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", path],
    "trivy-license": lambda path: ["trivy", "fs", "--scanners", "license", "--format", "json", "--quiet", path],
    "gosec": lambda path: ["gosec", "-fmt=json", "-quiet", "./..."],
    # IaC scanners (issue #75). `--soft-fail`/exit-code-0-on-findings
    # equivalents matter here the same way gitleaks' --exit-code 0 does
    # above: run_tool below only treats a genuinely nonzero *unexpected*
    # exit as an error, but explicit soft-fail keeps checkov/tfsec's own
    # "findings present" exit code from ever being ambiguous with a real
    # execution failure.
    "checkov": lambda path: ["checkov", "-d", path, "--output", "json", "--compact", "--quiet", "--soft-fail"],
    "tfsec": lambda path: ["tfsec", path, "--format", "json", "--soft-fail"],
    # Model-file scanning (issue #186). `-o` is filled in by run_tool below,
    # not here; see MODELSCAN_REPORT_PLACEHOLDER for why modelscan can't
    # just write JSON to stdout like every other tool.
    "modelscan": lambda path: ["modelscan", "-p", path, "-r", "json", "-o", MODELSCAN_REPORT_PLACEHOLDER],
}

# modelscan is the one tool here whose JSON can't be read off stdout.
# Verified against modelscan 0.8.8:
#   - `-r json` with no `-o` interleaves progress lines ("Scanning <file>
#     using modelscan.scanners...") with the JSON on *stdout*, so the stream
#     isn't parseable as a document.
#   - `-o /dev/stdout` routes it through rich's console renderer, which hard
#     -wraps at terminal width and corrupts the JSON mid-token.
# So run_tool substitutes a real temp file for this placeholder and reads the
# report back from disk.
MODELSCAN_REPORT_PLACEHOLDER = "__TOLEMAN_MODELSCAN_REPORT__"

# (#253) Same substitution for gitleaks; see its TOOL_COMMANDS entry.
GITLEAKS_REPORT_PLACEHOLDER = "__TOLEMAN_GITLEAKS_REPORT__"

# (#255) noseyparker scans into a datastore, then reports out of it.
NOSEYPARKER_DATASTORE_PLACEHOLDER = "__TOLEMAN_NOSEYPARKER_DATASTORE__"


class ToolExecutionError(Exception):
    """A scanner failed to execute (as opposed to running fine and finding
    nothing). Raised where a tool's exit code genuinely means "I broke",
    so scan_tasks marks the Scan failed instead of recording an empty,
    successful-looking result; a scan that silently reports zero findings
    because the tool crashed is a false all-clear.
    """


class RepoCloneError(Exception):
    """Raised for a repo_url/branch that fails validation before ever
    reaching subprocess. Deliberately NOT a subprocess.CalledProcessError
    subclass, and deliberately not retried by Celery (see
    app/tasks/scan_tasks.py RETRYABLE_EXCEPTIONS); bad input won't become
    good input on retry.
    """


class ToolNotApplicable(Exception):
    """Diff-scoped scanning (#243) left this tool with nothing to examine,
    e.g. trivy when the PR changed no dependency manifest, or tfsec when it
    changed no Terraform.

    Deliberately an exception and deliberately NOT a ToolExecutionError.
    Three states have to stay distinguishable, because collapsing any two of
    them produces a false all-clear:

        ran, found nothing   -> a real clean result
        did not run          -> this exception; nothing was checked
        broke                -> ToolExecutionError; the check is unreliable

    Returning an empty finding list here would merge the first two, which is
    the exact bug osv_malware.py's None-vs-{} distinction exists to prevent
    (issue #229). The caller records these as *skipped*, with the reason.
    """


def _validate_repo_url(repo_url: str) -> None:
    """Reject anything that isn't a well-formed https:// URL on an allowed
    host before it can reach `git clone`'s argv.

    This is the fix for the git-clone argument injection: a repo_url like
    "--upload-pack=/bin/sh" would otherwise be parsed by git as a flag (not
    a positional URL) since nothing validated the value or separated
    positional args from options. Requiring a real https:// scheme plus a
    host in ALLOWED_CLONE_HOSTS means a value starting with "-" can never
    pass validation, so it can never reach the subprocess call at all;
    independent of (and in addition to) the "--" positional separator below.
    """
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RepoCloneError(f"repo_url must be an https:// URL, got: {repo_url!r}")
    # (#298) settings.extra_clone_hosts_set is operator-configured (an env
    # var), never anything an API caller can influence, so unioning it here
    # extends the allowlist without weakening the SSRF defense it exists
    # for: an end user still can't point a Target at an arbitrary host,
    # only at one the deployment's operator explicitly opted into (e.g. an
    # internal GitHub Enterprise Server/GitLab/Gitea reachable via VPN or
    # gated behind a client certificate).
    allowed_hosts = ALLOWED_CLONE_HOSTS | settings.extra_clone_hosts_set
    if parsed.netloc not in allowed_hosts:
        raise RepoCloneError(
            f"repo_url host {parsed.netloc!r} is not supported (allowed: {sorted(allowed_hosts)})"
        )
    if not parsed.path or parsed.path == "/":
        raise RepoCloneError(f"repo_url is missing a repository path: {repo_url!r}")


def _validate_branch(branch: str) -> None:
    """Defense in depth alongside the "--" separator in the clone argv: a
    branch value starting with "-" could otherwise be mistaken for a flag
    by some argument parsers, so reject it outright rather than rely solely
    on positional separation."""
    if not branch or branch.startswith("-"):
        raise RepoCloneError(f"invalid branch name: {branch!r}")


def clone_repo(
    repo_url: str,
    branch: str,
    github_token: str = "",
    scan_id: int | str | None = None,
    client_cert_pem: str = "",
    client_key_pem: str = "",
    proxy_url: str = "",
) -> Path:
    """Clone repo_url@branch into a scan-scoped workdir.

    The destination is keyed by repo name AND a unique suffix (the caller's
    scan_id when available, otherwise a fresh UUID) so that two concurrent
    scans of the same target (or of different targets that happen to
    share a repo name) never resolve to the same directory. Previously
    the dir was keyed by repo name alone and unconditionally rmtree'd +
    recloned on every call, which let one scan's rmtree delete files while
    another scan's clone/tool run was still reading them (a race that could
    corrupt or blow up a concurrent scan). Cleaning up old scan workdirs is
    a separate ops concern, intentionally out of scope here.

    Security notes (see also _validate_repo_url/_validate_branch above):
    - repo_url/branch are validated *before* anything else runs, so a
      malicious Target.repo_url (any authenticated user who can create a
      target controls this) is rejected outright instead of reaching git.
    - The clone argv also puts "--" before the positional repo_url, so even
      a validated-but-unusual URL can never be misparsed as a flag.
    - github_token is never embedded in the URL and never appears anywhere
      in the subprocess argv. It's injected as an `http.extraHeader` via
      GIT_CONFIG_* environment variables (git >= 2.31), which git reads out
      of the environment rather than the command line. That matters because
      subprocess.CalledProcessError's str()/repr() includes the full argv
      verbatim; if the token were on the command line (e.g. via `git -c
      http.extraHeader=...` as an argv entry), it would leak into any log
      line or API response that ever surfaces str(exc) for a failed clone.
    - The header uses HTTP Basic (base64 "x-access-token:<token>"), not
      Bearer. app.core.github_token.resolve_github_token returns either a
      workspace-stored PAT (ghp_/github_pat_) or a GitHub App installation
      token. Basic works for all three token shapes, so it's used
      unconditionally rather than branching on token prefix.
    - github_token is only ever attached when repo_url's host is actually
      github.com (#298). resolve_github_token resolves a workspace's stored
      PAT independent of which Target asked for it, so without this guard
      a workspace with a GitHub PAT configured would send that PAT, as an
      HTTP Basic header, to any other allowed host (extra_clone_hosts) a
      Target happened to point at -- a real credential leak to a host the
      token was never meant for. client_cert_pem/client_key_pem/proxy_url
      are the credential path for those other hosts instead.
    - client_cert_pem/client_key_pem (#298, VPN/client-cert-gated hosts):
      written to 0600 temp files for the duration of this call only (never
      passed as argv, same reasoning as github_token) and wired in via
      http.sslCert/http.sslKey using the same GIT_CONFIG_* mechanism as the
      auth header above. Always deleted in `finally`, clone success or not.
    - proxy_url (#298, VPN-gated hosts reached through a corporate HTTP(S)
      proxy/gateway): set as HTTPS_PROXY/HTTP_PROXY, which git's libcurl
      HTTP backend honours natively; no extra plumbing needed beyond that.
    """
    _validate_repo_url(repo_url)
    _validate_branch(branch)

    workdir = Path(settings.scan_workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    unique = str(scan_id) if scan_id is not None else uuid.uuid4().hex
    dest = workdir / f"{repo_name}-{unique}"
    if dest.exists():
        shutil.rmtree(dest)

    cmd = ["git", "clone", "--depth", "1", "--branch", branch, "--", repo_url, str(dest)]

    env = os.environ.copy()
    git_configs: list[tuple[str, str]] = []

    is_github = urlparse(repo_url).netloc == "github.com"
    if github_token and is_github:
        basic = base64.b64encode(f"x-access-token:{github_token}".encode()).decode()
        git_configs.append(("http.extraheader", f"Authorization: Basic {basic}"))

    cert_dir = tempfile.mkdtemp(prefix="toleman-clone-cert-") if (client_cert_pem or client_key_pem) else None
    cert_path = key_path = None
    try:
        if cert_dir:
            if client_cert_pem:
                cert_path = Path(cert_dir) / "client-cert.pem"
                cert_path.write_text(client_cert_pem)
                cert_path.chmod(0o600)
                git_configs.append(("http.sslCert", str(cert_path)))
            if client_key_pem:
                key_path = Path(cert_dir) / "client-key.pem"
                key_path.write_text(client_key_pem)
                key_path.chmod(0o600)
                git_configs.append(("http.sslKey", str(key_path)))

        for i, (key, value) in enumerate(git_configs):
            env[f"GIT_CONFIG_KEY_{i}"] = key
            env[f"GIT_CONFIG_VALUE_{i}"] = value
        if git_configs:
            env["GIT_CONFIG_COUNT"] = str(len(git_configs))

        if proxy_url:
            env["HTTPS_PROXY"] = proxy_url
            env["HTTP_PROXY"] = proxy_url

        try:
            # repo_url/branch are validated above (_validate_repo_url,
            # _validate_branch: https-only, host allowlist, no leading "-") and
            # the argv has a "--" positional separator before repo_url, so
            # neither can be mistaken for a git flag. No shell.
            subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        except subprocess.CalledProcessError as exc:
            # Defense in depth: argv above never contains the token, but scrub
            # stdout/stderr too in case git ever echoes config values back on
            # failure, so nothing downstream (logs, retried task state, an API
            # response) can leak it even if some caller reaches into .stderr.
            if github_token:
                exc.stderr = (exc.stderr or "").replace(github_token, "***REDACTED***")
                exc.stdout = (exc.stdout or "").replace(github_token, "***REDACTED***")

            # Turn a permanent failure into RepoCloneError so Celery stops
            # retrying it. A missing repo, a missing branch and absent
            # credentials are all facts about the world that three more attempts
            # will not change; see _classify_clone_stderr for why this matters
            # beyond tidiness.
            permanent = _classify_clone_stderr(exc.stderr or "")
            if permanent:
                raise RepoCloneError(permanent) from exc
            raise
        return dest
    finally:
        if cert_dir:
            shutil.rmtree(cert_dir, ignore_errors=True)


# Substrings git prints for causes that are permanent (retrying cannot fix
# them) paired with the message an operator can actually act on.
#
# Why this exists: clone_error_message used to reduce every failure to
# "git clone failed (exit code 128)". That was safe (it never echoes argv or
# a token) but it threw away the diagnosis along with the danger. A real
# deployment sat in a retry loop against two private repos with no
# credentials configured, and the only clue in the logs was the exit code;
# identical to what a deleted repo or a typo'd branch produces. Matching on
# git's own wording restores the "what do I do about it" without ever
# echoing the raw stderr, argv or paths back to a caller.
_PERMANENT_CLONE_FAILURES: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        ("could not read username", "authentication failed", "terminal prompts disabled"),
        "Repository requires authentication and no GitHub credentials are configured. "
        "Set GITHUB_TOKEN, or connect the GitHub App for this repository.",
    ),
    (
        ("repository not found",),
        "Repository not found. It may have been deleted or renamed, or the configured "
        "credentials may not grant access to it.",
    ),
    (
        ("remote branch", "couldn't find remote ref", "could not find remote branch"),
        "The configured branch does not exist in the remote repository. Check the "
        "target's default branch.",
    ),
    (
        ("access denied", "permission denied", "403 forbidden"),
        "Access denied by the remote. The configured credentials exist but lack "
        "permission for this repository.",
    ),
)


def clone_kwargs_for_target(target) -> dict:
    """(#298) Decrypt a Target's stored mTLS client cert/key and read its
    clone_proxy_url, in the shape clone_repo's client_cert_pem/
    client_key_pem/proxy_url kwargs expect. Centralized here (rather than
    duplicated in each of clone_repo's callers) so every caller decrypts the
    same way GitHubToken/resolve_github_token does (app.core.crypto),
    instead of reinventing it per call site.
    """
    from app.core.crypto import decrypt_secret

    return {
        "client_cert_pem": decrypt_secret(target.client_cert_ciphertext),
        "client_key_pem": decrypt_secret(target.client_key_ciphertext),
        "proxy_url": target.clone_proxy_url,
    }


def _classify_clone_stderr(stderr: str) -> str | None:
    """Actionable message for a permanently-failing clone, or None when the
    cause looks transient (network blip, remote hangup) and a retry is
    worth attempting.

    Returns only messages composed here (never the raw stderr) so a path,
    an argv or a redacted-but-present token can't reach a log or an API
    response through this route.
    """
    haystack = stderr.lower()
    for needles, message in _PERMANENT_CLONE_FAILURES:
        if any(n in haystack for n in needles):
            return message
    return None


def clone_error_message(exc: Exception) -> str:
    """Safe-for-API-response/log message for a clone_repo failure.

    Call sites that catch a broad `except Exception` around clone_repo (e.g.
    app/api/scans.py, app/core/pr_guardrail_executor.py) historically did
    `str(exc)` straight into an HTTP response / DB row. For a
    CalledProcessError that used to mean the full argv, including the
    embedded GitHub token, before this fix. The token can no longer reach
    argv (see clone_repo), but this still avoids echoing raw subprocess
    argv/paths back to callers as a matter of course.
    """
    if isinstance(exc, RepoCloneError):
        return str(exc)
    if isinstance(exc, subprocess.CalledProcessError):
        # Prefer a cause the reader can act on. _classify_clone_stderr only
        # ever returns strings composed in this module, so this stays free of
        # raw argv/paths/tokens; the exit code alone was safe but useless.
        classified = _classify_clone_stderr(exc.stderr or "")
        if classified:
            return classified
        return f"git clone failed (exit code {exc.returncode})"
    return str(exc)


def normalize_file_path(file_path: str, repo_path: Path) -> str:
    """Strip the scan-scoped clone directory prefix so file_path is relative
    to the repo root, e.g. "vulnerability/idor/idor.go" not
    "/tmp/toleman-scans/govwa-<scan-id>/vulnerability/idor/idor.go".

    This matters beyond cosmetics: compute_dedup_hash includes file_path, and
    since clone_repo (above) gives every scan its own unique directory name
    for isolation, an un-normalized absolute path made the dedup hash change
    on every single scan; silently defeating dedup entirely (every rescan
    created a new Finding instead of updating last_seen on the existing one).
    Call this on every parsed finding's file_path before hashing/persisting.
    """
    if not file_path:
        return file_path
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        # Already relative (some tools report paths relative to the scan
        # root they were invoked against); nothing to strip.
        return file_path


def _validate_scan_url(url: str) -> None:
    """Defense in depth for run_nuclei below: the caller (app.core.api_scan_targets)
    already builds these URLs from a Target's own operator-configured
    api_base_url plus its own persisted ApiEndpoint routes, and already
    confirms every URL's host matches api_base_url's host; so nothing
    here should ever actually reject a well-formed call. This exists purely
    so a future caller can't accidentally hand this function (and therefore
    a real subprocess invocation against the network) something that isn't
    a genuine http(s) URL with a real host, the same "validate before it
    ever reaches subprocess" discipline as _validate_repo_url above."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"nuclei scan URL must be http(s):// with a host, got: {url!r}")
    if url.startswith("-"):
        raise ValueError(f"invalid nuclei scan URL: {url!r}")


def run_nuclei(urls: list[str]) -> list[dict]:
    """Run nuclei against an already-validated list of live URLs and return
    parsed JSONL results (one dict per finding).

    Safety posture (issue #72: this is ACTIVE scanning against real
    network endpoints, unlike every other scanner in this module which only
    reads a git checkout):
      - Every URL is re-validated here (see _validate_scan_url) even though
        the caller already built/validated them, so this function is safe
        to call directly.
      - URLs are written to a temp file and passed via `-l <file>`, never
        joined into a shell string or passed as a single argv blob,
        avoids any injection surface from a route/host containing shell
        metacharacters.
      - `-etags` excludes disruptive template categories by default
        (settings.nuclei_exclude_tags: dos/fuzz/intrusive) so a first run
        defaults to passive/safe detection, not exploitation attempts.
      - `-rate-limit` bounds request rate against the target; `-timeout`
        bounds nuclei's per-request timeout; the subprocess itself is
        killed via subprocess.run(timeout=...) if the whole run hangs
        rather than blocking a Celery worker indefinitely.
      - `-no-interactsh` disables nuclei's out-of-band interaction server
        (an external network dependency this platform doesn't control);
        keeps scanning self-contained to what this process directly
        observes.
      - `-duc` (disable update check) is the nuclei half of #229, but only
        when a template store already exists. nuclei keeps its templates in
        one shared directory and rewrites it in place when it decides an
        update is due, so two concurrent runs can have one process replacing
        the templates the other is loading -- the same shape as the trivy DB
        race, and with the same ending: exit 0, valid JSONL, fewer findings.
        Disabling the update check stops a scan mutating that store.
        It is NOT passed on a host with no templates yet, because nuclei's
        fresh-install path sits behind the same update check: passing it
        there would leave nuclei with an empty template set, which is exit 0
        and zero findings from a scanner that loaded no checks at all. The
        image installs templates at build time (see backend/Dockerfile) so
        the normal path is the isolated one.
      - The exit code is checked (#253's lesson, which this function had
        been skipping because it does not go through _execute). nuclei is
        not given a findings-based exit code, so anything nonzero means it
        broke; returning [] for that is a false all-clear, and this is the
        one tool whose results reach ingest_findings via a path that
        asserts its own health.
    """
    if not urls:
        return []
    for url in urls:
        _validate_scan_url(url)

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        target_file = f.name

    try:
        cmd = [
            settings.nuclei_binary,
            "-l", target_file,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-rate-limit", str(settings.nuclei_rate_limit),
            "-timeout", "5",
        ]
        if nuclei_templates_present():
            cmd.append("-duc")
        if settings.nuclei_exclude_tags:
            cmd += ["-etags", settings.nuclei_exclude_tags]
        # cmd is built entirely from settings/constants above, no shell, no
        # interpolated repo content.
        proc = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            cmd, capture_output=True, text=True, timeout=settings.nuclei_timeout_seconds
        )
    finally:
        try:
            os.unlink(target_file)
        except OSError:
            pass

    if proc.returncode != 0:
        # (#229/#253) This function bypasses _execute, so it bypassed the
        # exit-code check every other tool got. A broken nuclei run used to
        # return [], which app.tasks.api_scan_tasks then ingested as a
        # completed, healthy, zero-finding scan -- mitigating every open
        # api-scan finding on the target.
        detail = _strip_ansi(proc.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "no stderr"
        raise ToolExecutionError(f"nuclei exited {proc.returncode}: {tail[:300]}")

    results = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


# Where nuclei keeps the templates it scans with: the defaults nuclei itself
# has used across v2 and v3, resolved from $HOME.
#
# Deliberately NOT configurable by an environment variable. An earlier
# version honoured a NUCLEI_TEMPLATES_DIR override, which was unsafe in one
# direction: run_nuclei passes nuclei no template-directory flag, so nuclei
# reads from $HOME regardless of what that variable said. Pointing it at a
# store nuclei does not use would make nuclei_templates_present() answer
# "definitely yes" for a directory nuclei never opens, `-duc` would be
# passed, and the scan would run with an empty template set -- exit 0, zero
# findings, reported as a clean API. That is precisely the false positive
# the docstring below says this function must never produce, so the knob is
# gone rather than documented. If a template store ever does need to move,
# it has to move for nuclei too (a flag in run_nuclei), not just for us.
def _nuclei_template_dirs() -> list[Path]:
    home = Path.home()
    return [
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        home / ".config" / "nuclei" / "nuclei-templates",
    ]


def nuclei_templates_present() -> bool:
    """Is there a template store for nuclei to scan with?

    Governs `-duc` (see run_nuclei). A false negative costs one update
    check; a false positive costs a scan with no templates reported as a
    clean API -- so this answers "definitely yes" or "assume not".
    """
    for candidate in _nuclei_template_dirs():
        try:
            if candidate.is_dir() and any(candidate.iterdir()):
                return True
        except OSError:
            continue
    return False


def _run_noseyparker(
    cmd: list[str], cwd: str | None, run: "ScanRunContext", env: dict[str, str] | None = None
) -> list:
    """Scan into a temp datastore, then report out of it (#255).

    Unlike every other tool here, noseyparker's scan step writes no findings
    to stdout; the datastore is the output, and `report` renders it. Both
    steps' exit codes are checked: a scan that died leaves an empty datastore,
    and an empty datastore renders as `[]`, which is the false all-clear #253
    was about arriving through a new door.
    """
    datastore = Path(tempfile.mkdtemp(prefix="toleman-np-")) / "datastore"
    scan_cmd = [str(datastore) if c == NOSEYPARKER_DATASTORE_PLACEHOLDER else c for c in cmd]
    try:
        # scan_cmd is the caller's fixed argv with only the datastore path
        # substituted in, no shell.
        proc = subprocess.run(scan_cmd, capture_output=True, text=True, cwd=cwd, env=env)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        if proc.returncode != 0:
            detail = _strip_ansi(proc.stderr or "").strip().splitlines()
            raise ToolExecutionError(
                f"noseyparker scan exited {proc.returncode}: {(detail[-1] if detail else 'no stderr')[:300]}"
            )
        # (#229) These three tools return before _execute's stderr check,
        # so they need their own: a warning about the tool's own inputs is
        # the difference between "found nothing" and "could not look".
        _note_stderr("noseyparker", proc.stderr, run.health)
        report = subprocess.run(
            ["noseyparker", "report", "--datastore", str(datastore), "--format", "json"],
            capture_output=True, text=True, cwd=cwd, env=env,
        )
        if report.returncode != 0:
            detail = _strip_ansi(report.stderr or "").strip().splitlines()
            raise ToolExecutionError(
                f"noseyparker report exited {report.returncode}: {(detail[-1] if detail else 'no stderr')[:300]}"
            )
        text = (report.stdout or "").strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(f"noseyparker produced unreadable JSON: {exc}") from exc
    finally:
        shutil.rmtree(datastore.parent, ignore_errors=True)


def _run_gitleaks(
    cmd: list[str], cwd: str | None, run: "ScanRunContext", env: dict[str, str] | None = None
) -> list:
    """Run gitleaks with its report going to a real file (#253).

    Substitutes GITLEAKS_REPORT_PLACEHOLDER for a temp path, then reads the
    report back. `--exit-code 0` means findings do not affect the exit
    status, so any nonzero exit here is a genuine execution failure and
    becomes a ToolExecutionError rather than an empty, clean-looking result.
    """
    report_path = Path(tempfile.mkdtemp(prefix="toleman-gitleaks-")) / "report.json"
    resolved = [str(report_path) if c == GITLEAKS_REPORT_PLACEHOLDER else c for c in cmd]
    try:
        # resolved is the caller's fixed argv with only the report path
        # substituted in, no shell.
        proc = subprocess.run(resolved, capture_output=True, text=True, cwd=cwd, env=env)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        if proc.returncode != 0:
            detail = _strip_ansi(proc.stderr or "").strip().splitlines()
            tail = detail[-1] if detail else "no stderr"
            raise ToolExecutionError(f"gitleaks exited {proc.returncode}: {tail[:300]}")
        _note_stderr("gitleaks", proc.stderr, run.health)  # (#229)
        if not report_path.exists():
            # Exited 0 but wrote nothing. Do not assume "clean"; gitleaks
            # writes a report (even `[]`) on every successful run.
            raise ToolExecutionError("gitleaks exited 0 but produced no report file")
        text = report_path.read_text().strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(f"gitleaks produced unreadable JSON: {exc}") from exc
    finally:
        shutil.rmtree(report_path.parent, ignore_errors=True)


def _run_modelscan(
    cmd: list[str], run: "ScanRunContext", env: dict[str, str] | None = None
) -> dict:
    """Run modelscan with its report directed at a temp file and read it back
    (issue #186). See MODELSCAN_REPORT_PLACEHOLDER for why stdout is unusable.

    Exit codes are modelscan's own and do NOT follow the usual convention:
        0  scan ok, nothing found
        1  scan ok, *vulnerabilities found*   <- success, not failure
        2  modelscan itself errored
        3  no supported files provided
        4  invalid CLI options
    Only 2 and 4 are real failures. Treating 1 as an error would discard
    exactly the findings this tool exists to produce; the same hazard
    checkov/tfsec avoid above with --soft-fail, which modelscan has no
    equivalent of.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "modelscan-report.json"
        resolved = [str(report_path) if part == MODELSCAN_REPORT_PLACEHOLDER else part for part in cmd]
        # resolved is the caller's fixed argv with only the report path
        # substituted in, no shell.
        proc = subprocess.run(resolved, capture_output=True, text=True, env=env)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit

        if proc.returncode in (2, 4):
            raise ToolExecutionError(f"modelscan failed (exit {proc.returncode})")

        _note_stderr("modelscan", proc.stderr, run.health)  # (#229)

        if not report_path.exists():
            # Exit 3 (nothing supported to scan) legitimately writes no
            # report. That is a clean, successful scan of a repo with no
            # model files; not an error, and not a silent skip.
            return {"summary": {"total_issues": 0}, "issues": [], "errors": []}

        try:
            return json.loads(report_path.read_text())
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(f"modelscan produced unreadable JSON: {exc}") from exc


# --- Diff-scoped scanning (#243) -------------------------------------------
# Scanning only a PR's changed files needs per-tool knowledge, because the
# CLIs genuinely disagree about what "scan these files" means. Keeping that
# knowledge here, next to TOOL_COMMANDS, stops it leaking into the PR
# guardrail executor as a pile of `if tool == ...`.
#
#   MULTI_PATH   the command takes N paths; append them all
#   PER_FILE     the command takes exactly one path; invoke once per file and
#                merge the reports
#   MANIFEST     not file-oriented at all. Trivy resolves dependency
#                manifests, so "only these files changed" is meaningless to
#                it; the honest scoping question is *whether a manifest
#                changed*, answered by manifest_changed() below, not by
#                handing it a file list.
#   PACKAGE      gosec walks Go packages from cwd, so changed .go files map
#                to their containing package directories.
MULTI_PATH = "multi_path"
PER_FILE = "per_file"
MANIFEST = "manifest"
PACKAGE = "package"

TOOL_SCOPING = {
    "semgrep": MULTI_PATH,
    "semgrep-llm": MULTI_PATH,
    "checkov": MULTI_PATH,
    "gitleaks": PER_FILE,
    "noseyparker": MULTI_PATH,
    "tfsec": PER_FILE,
    "modelscan": PER_FILE,
    "gosec": PACKAGE,
    "trivy": MANIFEST,
    "trivy-license": MANIFEST,
}

# Files whose change means the resolved dependency set may have moved, so a
# MANIFEST tool has something new to say. Lockfiles included deliberately:
# a lockfile bump with an untouched manifest is exactly the transitive
# upgrade case, which is the one #239 is about.
MANIFEST_FILENAMES = frozenset({
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
    "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "uv.lock", "pdm.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
    "packages.config", "paket.lock",
    "mix.exs", "mix.lock",
    "conan.lock", "vcpkg.json",
    "Dockerfile",
})

# The IaC and model scanners only have anything to say about their own file
# types. Handing gitleaks a .tf file is harmless; handing tfsec a .py file is
# a wasted process per file, which matters when PER_FILE means one process
# each. None = no extension filter (gitleaks scans anything).
TOOL_EXTENSIONS = {
    "tfsec": (".tf", ".tfvars", ".hcl"),
    "checkov": (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".template"),
    "modelscan": (".pkl", ".pickle", ".pt", ".pth", ".bin", ".h5", ".keras", ".pb", ".onnx", ".safetensors", ".joblib", ".dill", ".npy", ".npz"),
}


def manifest_changed(paths: list[str]) -> bool:
    """Does this change touch anything that could move the resolved
    dependency set? Governs whether a MANIFEST tool runs at all."""
    for p in paths:
        name = PurePosixPath(p).name
        if name in MANIFEST_FILENAMES or name.startswith("Dockerfile"):
            return True
    return False


def paths_for_tool(tool: str, paths: list[str]) -> list[str]:
    """Narrow a changed-file list to the files this tool can say something
    about. An empty result means "nothing here for this tool"; the caller
    must record that as *skipped*, never as a clean run."""
    exts = TOOL_EXTENSIONS.get(tool)
    if exts is None:
        return list(paths)
    return [p for p in paths if p.lower().endswith(exts)]


def go_packages_for(paths: list[str]) -> list[str]:
    """Changed .go files -> the package directories gosec should walk.

    A file at the repo root maps to "." (that package only), never "./...";
    the recursive form would walk the entire module while the scan still
    reported itself as diff-scoped, which is the one outcome this feature
    must never produce.
    """
    dirs = {str(PurePosixPath(p).parent) for p in paths if p.endswith(".go")}
    return sorted("." if d == "." else "./" + d for d in dirs)


def _merge_reports(reports: list[dict | list]) -> dict | list:
    """Combine several single-path runs into one report of the same shape the
    tool would have produced for a single invocation, so parsers don't need
    to know whether scoping happened."""
    if not reports:
        return []
    if isinstance(reports[0], list):
        merged: list = []
        for r in reports:
            if isinstance(r, list):
                merged.extend(r)
        return merged
    merged_dict: dict = {}
    for r in reports:
        if not isinstance(r, dict):
            continue
        for key, value in r.items():
            if isinstance(value, list):
                merged_dict.setdefault(key, []).extend(value)
            else:
                merged_dict.setdefault(key, value)
    return merged_dict


# --- Concurrent-run isolation and scan health (#229) -----------------------
#
# Two defects, one issue. Both are about a scan that did not really run
# looking exactly like a scan that passed.
#
# 1. Shared mutable tool state. trivy keeps its vulnerability DB in one
#    per-user cache directory ($TRIVY_CACHE_DIR, default $HOME/.cache/trivy)
#    and replaces it in place when it decides an update is due. A second
#    trivy reading it mid-replacement finishes happily: exit 0, valid JSON,
#    and either an empty Results list or Results whose Vulnerabilities
#    arrays are empty. That is what #229 reproduced -- six concurrent scans,
#    one of which reported a repo with five live CVEs as clean, while the
#    same command run alone four minutes later found all five.
#
#    The fix is NOT to hardlink out of that shared directory. A hardlink
#    shares an inode, so an in-place writer -- which is precisely what the
#    issue's own diagnosis says trivy is -- reaches straight through it.
#    Instead Toleman keeps its *own* warm copy under settings.tool_cache_dir
#    that nothing writes except ensure_warm_trivy_db, which downloads into a
#    staging directory and publishes it by replacing the warm directory
#    whole, under an exclusive lock, while seeders hold a shared one. A
#    published generation is therefore never written again, which is what
#    makes hardlinking from it an actual snapshot. Each run hardlinks into
#    its own TRIVY_CACHE_DIR and passes --skip-db-update, so no scan process
#    can be the thing rewriting a DB another scan is reading.
#
#    semgrep is treated more narrowly on purpose: the file it genuinely
#    rewrites on every run is its settings file, and that gets isolated. Its
#    registry rule cache is left shared, because giving every run a private
#    empty one would re-download the whole ruleset per scan -- trading a
#    race for a guaranteed cost, which is the trap the warm copy above
#    exists to avoid. nuclei is handled in run_nuclei (see `-duc` there).
#
# 2. A zero-finding result being trusted unconditionally. Isolation makes
#    the race very unlikely; it does not make an empty result *provable*,
#    and it does nothing for a DB that is simply broken or months stale. So
#    each run also collects evidence about itself into a ScanHealth --
#    whether the database behind it was actually usable (a real file of a
#    plausible size, with metadata that parses and is not long past its own
#    refresh deadline), whether that database changed underneath the running
#    scan, warnings the tool wrote to stderr, and whether it produced a
#    report at all -- and app.core.ingestion refuses to mitigate existing
#    findings off a run that is not positively healthy. Zero vulnerabilities
#    is accepted as a clean result only when the database behind it has been
#    verified; that is the requirement #229's reproduction failed, whether
#    it surfaced as an empty Results list or as Results with empty
#    Vulnerabilities. Same rule osv_malware.py already applies with its
#    None-vs-{} return; see app/core/scan_health.py.


@dataclass
class ScanRunContext:
    """Everything one tool run needs beyond its argv.

    Passed explicitly down through run_tool_checked -> _run_tool_inner ->
    _execute rather than carried in a ContextVar. A ContextVar would be
    correct only for a plain synchronous call stack: ThreadPoolExecutor and
    loop.run_in_executor do not propagate one, and under eventlet two runs
    can share a context and read -- then rmtree -- each other's cache
    directory. Every one of those failures is silent and biased toward
    "clean", which is the exact direction this issue says never to fail in.
    An explicit parameter fails loudly at the call site instead.
    """

    tool: str
    health: ScanHealth
    # Environment for the tool's subprocess. None means "inherit ours".
    env: dict[str, str] | None = None
    # This run's private TRIVY_CACHE_DIR, when it got one.
    trivy_cache: Path | None = None
    # The run's private cache root, removed when the run ends.
    cache_dir: Path | None = None
    # Whether the private cache was populated from the warm copy. Governs
    # whether trivy may be told --skip-db-update: telling it to skip the
    # update when it has no DB at all would turn every scan on a cold cache
    # into a hard failure.
    seeded: bool = False
    # (size, mtime_ns) of the private DB before the tool ran, so a change
    # underneath a running scan is detectable rather than assumed away.
    db_fingerprint: tuple | None = None


# Layout under settings.tool_cache_dir.
TRIVY_WARM_DIRNAME = "trivy-warm"
TRIVY_STAGING_PREFIX = "trivy-staging-"
RUN_CACHE_DIRNAME = "runs"
CACHE_LOCK_FILENAME = "trivy-warm.lock"

# Per-run caches are removed in a finally block, but a worker killed by
# SIGKILL or the OOM killer never reaches it -- and with task_acks_late that
# is an expected path, not a rare one. Anything older than this is from a
# run that cannot still be alive: the stale-job timeout
# (settings.stale_job_timeout_seconds, 15 minutes) is an order of magnitude
# below it, so this can never delete a cache a live scan is using.
RUN_CACHE_MAX_AGE_SECONDS = 6 * 60 * 60

# Where trivy puts the DB and its metadata inside a cache directory.
TRIVY_DB_FILE_PATH = "db/trivy.db"
TRIVY_DB_METADATA_PATH = "db/metadata.json"

# Floor on a believable trivy.db. A complete one is hundreds of megabytes;
# this is not a completeness check (the format is trivy's to change) but a
# truncation check -- a partially-written or zero-length file is the shape a
# mid-download or mid-replacement read leaves behind, and that file must
# never be read as "checked, nothing found".
MIN_TRIVY_DB_BYTES = 32 * 1024 * 1024

# How far past trivy's own declared NextUpdate the DB has to be before a run
# against it stops counting as evidence. NextUpdate passing is routine
# (trivy publishes every few hours and refreshes opportunistically); days
# past it means the refresh has been failing, and anything published since
# cannot be found.
TRIVY_DB_STALE_GRACE_HOURS = 72

# How long a scan will wait for another process to finish warming the DB
# before giving up and running unseeded. Bounded because this is called from
# a Celery task: the first of six concurrent scans downloads while the other
# five wait here, which is the point, but none of them may wait forever.
WARM_LOCK_TIMEOUT_SECONDS = 600

# How long the download itself may take, bounded separately from the lock.
# It runs while holding LOCK_EX, so an unbounded download is an unbounded
# hold: every other scan in a fan-out queues behind it, and Celery's own
# stale_job_timeout_seconds (900) keeps counting meanwhile. Left unbounded,
# one slow first download could get the rest of the fan-out marked
# stale-failed -- the warming path manufacturing the outage it exists to
# prevent. Deliberately well inside that 900s budget so a scan that waited
# still has time to clone and run.
WARM_DOWNLOAD_TIMEOUT_SECONDS = 420
SEED_LOCK_TIMEOUT_SECONDS = 60

# Lockfiles whose presence means this repository's dependencies really are
# resolved, so trivy reporting *no package sources at all* contradicts the
# checkout in front of it.
#
# Deliberately lockfiles only, and deliberately not MANIFEST_FILENAMES.
# That list exists to answer "could a diff have moved the dependency set",
# which is a much lower bar: it includes Dockerfile, package.json, setup.py
# and pyproject.toml, none of which guarantee trivy emits a Results entry.
# Firing on those would leave Dockerfile-only repos, and any repo with a
# package.json and no lockfile, permanently unable to mitigate anything --
# the same trap SUSPECT_STDERR_MARKERS is narrow to avoid.
RESOLVED_LOCKFILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
    "go.sum", "Gemfile.lock", "Cargo.lock", "composer.lock",
    "gradle.lockfile", "paket.lock", "mix.lock", "conan.lock",
})

# A lockfile can legitimately resolve to nothing ({"packages":{}} in a fresh
# npm project), and trivy emits no Results entry for one that does. Requiring
# some substance keeps the heuristic off those repos.
MIN_LOCKFILE_BYTES = 512

# Substrings a scanner writes to stderr when part of the work it was asked
# to do did not actually happen. Matched case-insensitively anywhere in the
# stream.
#
# Each entry is about the tool's *inputs* (its database, its rules, the
# network it needed to fetch them) rather than about one file in the
# checkout. "failed to analyze <file>" and "no such file or directory" were
# considered and left out for that reason: both fire on an ordinary repo
# containing a broken symlink or an unreadable binary, and a marker that
# fires routinely would block mitigation forever on repositories where
# nothing is actually wrong.
SUSPECT_STDERR_MARKERS = (
    "failed to download",
    "unable to open db",
    "unable to open the database",
    "failed to open the database",
    "unable to initialize",
    "failed to initialize",
    "db error",
    "database error",
    "context deadline exceeded",
    "i/o timeout",
    "connection refused",
    "too many requests",
    "partial results",
)


def tool_cache_root() -> Path:
    return Path(settings.tool_cache_dir)


def trivy_warm_dir() -> Path:
    return tool_cache_root() / TRIVY_WARM_DIRNAME


def _run_cache_root() -> Path:
    return tool_cache_root() / RUN_CACHE_DIRNAME


@contextmanager
def _cache_lock(exclusive: bool, timeout_seconds: float):
    """Coordinate warmers against seeders across processes.

    A seeder takes a shared lock for the few milliseconds it spends
    hardlinking; a warmer takes the exclusive one for as long as the
    download takes. Without this, a warmer could replace the warm directory
    halfway through a seeder's copy, which is the very race being fixed one
    level up.

    Polled rather than blocking: a blocking flock cannot be bounded, and
    this runs inside a Celery task that must not hang forever on a warmer
    that died holding the lock. Yields True when the lock was acquired and
    False on timeout; the caller decides what a missed lock means (a seeder
    proceeds unseeded, a warmer gives up and lets the next scan try).
    """
    root = tool_cache_root()
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / CACHE_LOCK_FILENAME
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    handle = open(lock_path, "a+")
    acquired = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
        yield acquired
    finally:
        if acquired:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


def sweep_stale_run_caches() -> int:
    """Remove per-run caches left behind by a worker that was killed.

    Cheap enough to run at the start of every run (one listdir), which is
    the only sweeper this gets: there is no cron in this project, and a
    directory that only grows is how a disk fills up quietly.

    Covers two roots, because warming leaves its own debris. A SIGKILL or
    OOM between ensure_warm_trivy_db's two renames strands a
    ``trivy-warm.replaced-*`` directory, and one during the download
    strands a ``trivy-staging-*`` one -- each a full copy of the database,
    which is the largest thing this platform writes to disk. The happy
    paths remove both; nothing else did.
    """
    cutoff = time.time() - RUN_CACHE_MAX_AGE_SECONDS
    removed = 0

    def _sweep(root: Path, matches) -> int:
        if not root.is_dir():
            return 0
        try:
            entries = list(root.iterdir())
        except OSError:
            return 0
        count = 0
        for entry in entries:
            if not matches(entry):
                continue
            try:
                if entry.stat().st_mtime >= cutoff:
                    continue
            except OSError:
                continue
            shutil.rmtree(entry, ignore_errors=True)
            count += 1
        return count

    removed += _sweep(_run_cache_root(), lambda _entry: True)
    removed += _sweep(
        tool_cache_root(),
        lambda entry: entry.name.startswith(TRIVY_STAGING_PREFIX)
        or entry.name.startswith(f"{TRIVY_WARM_DIRNAME}.replaced-"),
    )
    return removed


def _parse_trivy_timestamp(value) -> datetime | None:
    """Parse trivy's RFC3339 metadata timestamps.

    Go writes nanosecond precision, which datetime.fromisoformat rejects
    (it accepts 3 or 6 fractional digits), so the fraction is trimmed before
    parsing rather than reaching for a dependency.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    match = re.match(r"^(.*\.\d{1,6})\d*(.*)$", text)
    if match:
        text = match.group(1) + match.group(2)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def trivy_db_state(cache_dir: Path) -> tuple[bool, str]:
    """Is there a usable vulnerability database in ``cache_dir``?

    Returns ``(ok, reason_if_not)``. This is the evidence that decides
    whether zero vulnerabilities may be read as a clean repository, so it
    checks the database *file*, not just the metadata beside it: a cache
    caught mid-replacement can carry perfectly parseable metadata next to a
    trivy.db that is missing or half-written, and metadata alone would wave
    that through -- which is how #229's reproduction reported clean.
    """
    db_file = cache_dir / TRIVY_DB_FILE_PATH
    if not db_file.is_file():
        return False, "there was no vulnerability database file (db/trivy.db), so no CVE could have been found"
    try:
        size = db_file.stat().st_size
    except OSError:
        return False, "the vulnerability database file could not be read"
    if size < MIN_TRIVY_DB_BYTES:
        return False, (
            f"the vulnerability database file is only {size} bytes, far short of a complete one "
            "(truncated, or still being written)"
        )
    metadata_file = cache_dir / TRIVY_DB_METADATA_PATH
    if not metadata_file.is_file():
        return False, "the vulnerability database carries no metadata, so its contents cannot be vouched for"
    try:
        metadata = json.loads(metadata_file.read_text())
    except (OSError, ValueError):
        return False, "the vulnerability database metadata was unreadable"
    if not isinstance(metadata, dict) or not metadata.get("Version"):
        return False, "the vulnerability database metadata declares no schema version"
    next_update = _parse_trivy_timestamp(metadata.get("NextUpdate"))
    if next_update is None:
        return False, "the vulnerability database does not say when it is next due for refresh"
    overdue_by = datetime.now(timezone.utc) - next_update
    if overdue_by > timedelta(hours=TRIVY_DB_STALE_GRACE_HOURS):
        return False, (
            f"the vulnerability database is {overdue_by.days} day(s) past its own refresh deadline, "
            "so anything published since then cannot be found"
        )
    return True, ""


def _trivy_db_fingerprint(cache_dir: Path) -> tuple | None:
    """Identity of the DB behind a run, cheap enough to take twice.

    Compared before and after the scan. Nothing should be able to rewrite a
    private cache mid-run any more, but "should" is what #229 was built on;
    an actual before/after comparison is the difference between believing
    the DB was stable and knowing it.
    """
    try:
        db_stat = (cache_dir / TRIVY_DB_FILE_PATH).stat()
        meta_stat = (cache_dir / TRIVY_DB_METADATA_PATH).stat()
    except OSError:
        return None
    return (db_stat.st_size, db_stat.st_mtime_ns, meta_stat.st_size, meta_stat.st_mtime_ns)


def ensure_warm_trivy_db(timeout_seconds: float = WARM_LOCK_TIMEOUT_SECONDS) -> tuple[bool, str]:
    """Make sure Toleman's own warm copy of the trivy DB is present and fresh.

    Returns ``(warm, detail)``. Called before a scan fans out (see
    app.tasks.scan_tasks.run_scan) and on a schedule; NOT from run_tool, so
    running a tool never has a hidden network download inside it.

    This is what makes --skip-db-update reachable at all. Per-run caches are
    deleted when their run ends and nothing writes back to them, so without
    a warm copy that something maintains, six concurrent scans would mean
    six full database downloads -- a cost this platform would pay on every
    PR Guardrail scan too.

    The exclusive lock is the fan-out interlock the issue asks for: the
    first of N concurrent scans downloads while the rest wait here, then all
    of them hardlink the same finished database. A scan that cannot get the
    lock in time runs unseeded rather than waiting forever; it is slower and
    it does not get --skip-db-update, but it is not wrong.

    Publication is a whole-directory replace, never an in-place write, so a
    hardlink taken from a published generation can never be modified
    underneath the run holding it.

    NEVER RAISES. Every failure comes back as ``(False, detail)``. That is a
    requirement rather than an observation: both callers treat warming as
    best-effort and neither wraps it, so an exception here would take down
    the thing it exists to speed up. In run_scan it would fail the scan; in
    the PR Guardrail executor the call sits outside the per-tool try, so it
    would abort every tool on the PR. The guard lives here, with the
    contract, rather than at each call site where a third caller would have
    to remember it.
    """
    try:
        return _warm_trivy_db_unguarded(timeout_seconds)
    except Exception as exc:  # noqa: BLE001 -- see NEVER RAISES above
        logger.warning("trivy DB warming failed unexpectedly", exc_info=True)
        return False, f"warming failed unexpectedly ({exc.__class__.__name__})"


def _warm_trivy_db_unguarded(timeout_seconds: float) -> tuple[bool, str]:
    """The real work. Call ensure_warm_trivy_db, which guarantees the
    no-raise contract; this one may raise from anything it touches --
    tempfile.mkdtemp, or _cache_lock's own mkdir/open before it yields.
    """
    warm = trivy_warm_dir()
    ok, _ = trivy_db_state(warm)
    if ok:
        return True, "already warm"

    with _cache_lock(exclusive=True, timeout_seconds=timeout_seconds) as acquired:
        if not acquired:
            return False, "timed out waiting for another process to warm the database"
        # Re-check under the lock: whoever we queued behind has probably
        # just done this work for us.
        ok, _ = trivy_db_state(warm)
        if ok:
            return True, "warmed by another process"

        root = tool_cache_root()
        staging = None
        previous = None
        try:
            staging = Path(tempfile.mkdtemp(prefix=TRIVY_STAGING_PREFIX, dir=str(root)))
            # `trivy image --download-db-only` is the documented way to
            # fetch the DB and nothing else; it contacts no registry and
            # needs no image or daemon despite the subcommand's name.
            proc = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
                ["trivy", "image", "--download-db-only", "--cache-dir", str(staging)],
                capture_output=True, text=True, timeout=WARM_DOWNLOAD_TIMEOUT_SECONDS,
            )
            if proc.returncode != 0:
                detail = _strip_ansi(proc.stderr or "").strip().splitlines()
                return False, f"trivy exited {proc.returncode}: {(detail[-1] if detail else 'no stderr')[:200]}"
            ok, reason = trivy_db_state(staging)
            if not ok:
                # A download that "succeeded" into an unusable cache must
                # not be published; publishing it would hand every
                # subsequent scan a verified-looking database that is not
                # one.
                #
                # Note what this check is and is not. The real completeness
                # evidence is the exit code above: `--download-db-only`
                # verifies the OCI layer it pulled. trivy_db_state is a
                # structural sanity check, and it is deliberately the same
                # predicate every scan applies at read time -- which is
                # exactly why it must not be the only gate. One bad
                # publication that satisfies it would look verified to every
                # subsequent scan for as long as the DB stays inside its
                # freshness window.
                return False, f"downloaded database is not usable: {reason}"

            # Rotate-then-publish, with a rollback. The window between these
            # two renames is short but not empty, and a failure inside it
            # used to leave the install with no warm copy at all: every
            # later scan would run unseeded and re-download, which is the
            # cost this whole path exists to remove.
            if warm.exists():
                previous = root / f"{TRIVY_WARM_DIRNAME}.replaced-{uuid.uuid4().hex}"
                os.replace(warm, previous)
            try:
                os.replace(staging, warm)
            except OSError:
                if previous is not None and not warm.exists():
                    # Put the working copy back before giving up.
                    try:
                        os.replace(previous, warm)
                        previous = None
                    except OSError:
                        pass
                raise
            staging = None  # published; do not remove it below
            return True, "downloaded"
        except subprocess.TimeoutExpired:
            return False, f"the database download exceeded {WARM_DOWNLOAD_TIMEOUT_SECONDS:.0f}s"
        except FileNotFoundError:
            # No trivy binary on this host. Never fatal here: warming is a
            # best-effort optimisation, and a scan that cannot find trivy
            # fails loudly on its own in _execute.
            return False, "the trivy binary is not installed"
        except OSError as exc:
            return False, f"could not publish the warmed database ({exc.__class__.__name__})"
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            if previous is not None:
                shutil.rmtree(previous, ignore_errors=True)


def _seed_trivy_cache(private: Path) -> bool:
    """Hardlink the warm database into this run's private cache.

    Hardlinks, not copies, because the warm directory is only ever replaced
    whole (see ensure_warm_trivy_db) -- so a link into a published
    generation names a file nothing will write again, which is what makes it
    a snapshot rather than shared mutable state. The shared lock held here
    is what keeps a warmer from replacing the directory halfway through.
    """
    source = trivy_warm_dir() / "db"
    if not source.is_dir():
        return False
    destination = private / "db"

    def _link_or_copy(src: str, dst: str) -> None:
        """Hardlink the database itself; copy everything beside it.

        The database file is hundreds of megabytes and trivy has no reason
        to rewrite it under --skip-db-update, so linking it is what makes
        seeding cheap. Its metadata is a few hundred bytes, and a hardlink
        there is a standing bet that trivy never touches it in place -- a
        bet that costs the whole warm copy if it is ever wrong, because the
        write would land in the published generation every other run is
        linked to, the fingerprints would stop matching, and trivy would
        read as suspect on every scan from then on. Copying the small file
        removes the bet instead of testing it.
        """
        if Path(src).name == Path(TRIVY_DB_FILE_PATH).name:
            os.link(src, dst)
        else:
            shutil.copy2(src, dst)

    with _cache_lock(exclusive=False, timeout_seconds=SEED_LOCK_TIMEOUT_SECONDS) as acquired:
        if not acquired:
            return False
        try:
            shutil.copytree(source, destination, copy_function=_link_or_copy, dirs_exist_ok=True)
        except (OSError, shutil.Error):
            # Both directories live under settings.tool_cache_dir, so a
            # cross-device link should be impossible; if it happens anyway,
            # running unseeded is correct and a partial tree is not.
            shutil.rmtree(destination, ignore_errors=True)
            return False
    ok, _ = trivy_db_state(private)
    return ok


def _isolate_trivy(run_cache: Path) -> tuple[dict[str, str], bool, Path | None]:
    private = run_cache / "trivy"
    private.mkdir(parents=True, exist_ok=True)
    seeded = _seed_trivy_cache(private)
    return {"TRIVY_CACHE_DIR": str(private)}, seeded, private


def _isolate_semgrep(run_cache: Path) -> tuple[dict[str, str], bool, Path | None]:
    # Only the settings file, not XDG_CACHE_HOME. semgrep rewrites its
    # settings file on every single run, so concurrent runs genuinely race
    # it; its registry rule cache is left shared because handing each run an
    # empty private one would re-download the whole ruleset per scan.
    private = run_cache / "semgrep"
    private.mkdir(parents=True, exist_ok=True)
    return {"SEMGREP_SETTINGS_FILE": str(private / "settings.yml")}, False, None


# Tools with shared mutable state, and how to give one run a private copy.
# A tool absent here needs no isolation (gitleaks, gosec, tfsec, checkov and
# modelscan read the checkout and their own installed rules, and noseyparker
# already scans into a per-run temp datastore).
TOOL_CACHE_ISOLATION = {
    "trivy": _isolate_trivy,
    "trivy-license": _isolate_trivy,
    "semgrep": _isolate_semgrep,
    # semgrep-llm runs the in-repo ruleset rather than the registry, but it
    # is the same binary writing the same settings file, so it races the
    # same way.
    "semgrep-llm": _isolate_semgrep,
}


@contextmanager
def _isolated_run(tool: str, health: ScanHealth):
    """Give this run its own copy of ``tool``'s mutable state, then remove it."""
    isolate = TOOL_CACHE_ISOLATION.get(tool)
    run = ScanRunContext(tool=tool, health=health)
    run_cache: Path | None = None
    if isolate is not None:
        sweep_stale_run_caches()
        try:
            base = _run_cache_root()
            base.mkdir(parents=True, exist_ok=True)
            run_cache = Path(tempfile.mkdtemp(prefix=f"{tool}-", dir=str(base)))
            overrides, seeded, trivy_cache = isolate(run_cache)
            run.env = {**os.environ, **overrides}
            run.cache_dir = run_cache
            run.trivy_cache = trivy_cache
            run.seeded = seeded
            if trivy_cache is not None:
                run.db_fingerprint = _trivy_db_fingerprint(trivy_cache)
        except OSError as exc:
            # Falling back to the shared cache is worse than isolation but
            # better than failing the scan outright -- and the run is marked
            # suspect, so it cannot silently clear anything either way.
            if run_cache is not None:
                shutil.rmtree(run_cache, ignore_errors=True)
                run_cache = None
            run = ScanRunContext(tool=tool, health=health)
            health.degrade(
                f"could not isolate {tool}'s cache for this run ({exc.__class__.__name__}), "
                "so it shared mutable state with any concurrent scan"
            )
    try:
        yield run
    finally:
        if run_cache is not None:
            shutil.rmtree(run_cache, ignore_errors=True)


def _isolation_flags(tool: str, cmd: list[str], run: ScanRunContext) -> list[str]:
    """Per-tool argv additions that depend on the isolated cache.

    trivy only: with a seeded private DB there is nothing to update and no
    reason to let this process write one, so --skip-db-update makes the run
    deterministic and takes it out of the race entirely. Without a seeded DB
    the flag is omitted, because trivy refuses to scan with no database.
    """
    if not run.seeded:
        return cmd
    if tool in ("trivy", "trivy-license") and "--skip-db-update" not in cmd:
        # argv is ["trivy", "fs", ...]; the flag goes after the subcommand.
        return [*cmd[:2], "--skip-db-update", *cmd[2:]]
    return cmd


def _note_stderr(tool: str, stderr: str, health: ScanHealth) -> None:
    """Degrade the run for anything the tool said about not finishing.

    #253 taught this codebase that a crashed scanner must not read as a
    clean pass. This is the same lesson one notch quieter: the tool did not
    crash, and the only evidence is a line it wrote on the way past.
    """
    text = _strip_ansi(stderr or "").lower()
    if not text:
        return
    for marker in SUSPECT_STDERR_MARKERS:
        if marker in text:
            health.degrade(f'{tool} warned "{marker}" while scanning, so its results may be incomplete')


def has_resolved_lockfile(repo_path: Path) -> bool:
    """Does this checkout carry a lockfile with real content in it?

    `.git` is pruned: a packfile is not a lockfile and walking one is wasted
    work.
    """
    for _dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            if name not in RESOLVED_LOCKFILES:
                continue
            try:
                if os.path.getsize(os.path.join(_dirpath, name)) >= MIN_LOCKFILE_BYTES:
                    return True
            except OSError:
                continue
    return False


def _assess_trivy_run(repo_path: Path, raw: dict | list, run: ScanRunContext) -> None:
    """Post-run checks that need the report, the checkout and the cache.

    Scoped to ``trivy``. ``trivy-license`` runs with `--scanners license` and
    never loads the vulnerability database at all, so judging it on the
    database's state would mark every license scan suspect forever and leave
    license findings permanently unable to clear.
    """
    if run.tool != "trivy":
        return

    if run.trivy_cache is not None:
        ok, reason = trivy_db_state(run.trivy_cache)
        if not ok:
            run.health.degrade(f"trivy's vulnerability database was not usable for this run: {reason}")
        elif run.db_fingerprint is not None and _trivy_db_fingerprint(run.trivy_cache) != run.db_fingerprint:
            run.health.degrade(
                "trivy's vulnerability database changed while the scan was running, so the scan "
                "read it mid-replacement and cannot be treated as complete"
            )

    # trivy emits one Results entry per package source it resolved,
    # independently of whether anything in it was vulnerable. An empty
    # Results list from a checkout that carries a real lockfile therefore
    # means trivy resolved nothing at all -- a different statement from
    # "resolved your dependencies, none are vulnerable". Only the second is
    # a clean result, and only the second may clear existing findings.
    examined_something = isinstance(raw, dict) and bool(raw.get("Results"))
    if not examined_something and has_resolved_lockfile(repo_path):
        run.health.degrade(
            "trivy reported no package sources at all for a repository that contains a dependency "
            "lockfile, so it did not resolve this repository's dependencies"
        )


def run_tool_checked(
    tool: str, repo_path: Path, paths: list[str] | None = None
) -> tuple[dict | list, ScanHealth]:
    """``run_tool``, plus a verdict on whether this run can be trusted (#229).

    The raw report is the same value ``run_tool`` returns. The ScanHealth
    beside it is what lets a caller tell "scanned it, found nothing" from
    "produced nothing useful" -- the distinction ``osv_malware.py`` gets for
    free by returning None instead of {}, and that a scanner CLI's bytes
    cannot express on their own.

    Callers that intend to *clear* existing findings on a zero-finding
    result must use this and pass the health through to
    ``app.core.ingestion.ingest_findings``; ``run_tool`` remains for the
    paths that only want the report.
    """
    if tool not in TOOL_COMMANDS:
        raise ValueError(f"unsupported tool: {tool}")

    health = ScanHealth(tool=tool)
    with _isolated_run(tool, health) as run:
        raw = _run_tool_inner(tool, repo_path, paths, run)
        _assess_trivy_run(repo_path, raw, run)
    return raw, health


def run_tool(tool: str, repo_path: Path, paths: list[str] | None = None) -> dict | list:
    """Run ``tool`` over ``repo_path``.

    ``paths`` (repo-relative, from a PR's changed-file list) restricts the
    scan per TOOL_SCOPING above. ``None`` means scan everything, which stays
    the default for scheduled and default-branch scans.

    Raises ToolNotApplicable when scoping leaves this tool with nothing to
    look at. That is deliberately an exception rather than an empty result:
    an empty finding list from a tool that never examined a single file is
    indistinguishable from a clean pass, and this codebase does not allow
    that ambiguity (see osv_malware.py, issue #229).

    Cache isolation (#229) applies here too -- every run still gets its own
    private trivy cache and semgrep settings file. Only the health verdict
    is dropped, which is why any caller that mitigates findings has to use
    run_tool_checked instead.
    """
    return run_tool_checked(tool, repo_path, paths)[0]


def _run_tool_inner(
    tool: str, repo_path: Path, paths: list[str] | None, run: ScanRunContext
) -> dict | list:
    if paths is not None:
        return _run_tool_scoped(tool, repo_path, paths, run)

    # gosec's ./... walk fails outright (nonzero exit, no packages found)
    # on a repo with no Go source at all -- unlike the diff-scoped PACKAGE
    # strategy above, which already guards this via go_packages_for(), a
    # full/whole-repo scan (paths=None: scheduled scans, default-branch
    # baselines, and any PR Guardrail scan for a target that isn't
    # diff-scoped) had no equivalent guard. Every non-Go target's full scan
    # reported gosec as *failed*, indistinguishable from a broken install,
    # when the honest answer is "this repo has nothing for gosec to look
    # at" -- the same skip this codebase already gives modelscan/semgrep-llm
    # on a non-AI/ML repo (see scan_tasks.AI_ONLY_TOOLS).
    if tool == "gosec" and next(repo_path.rglob("*.go"), None) is None:
        raise ToolNotApplicable("no Go files in this repository")

    cmd = TOOL_COMMANDS[tool](str(repo_path))
    return _execute(tool, cmd, repo_path, run)


def _run_tool_scoped(
    tool: str, repo_path: Path, paths: list[str], run: ScanRunContext
) -> dict | list:
    strategy = TOOL_SCOPING.get(tool, MULTI_PATH)

    if strategy == MANIFEST:
        if not manifest_changed(paths):
            raise ToolNotApplicable(
                f"{tool} scans dependency manifests; no manifest or lockfile changed in this diff"
            )
        # A manifest did change, so resolution may have moved anywhere in the
        # tree; scan the whole checkout. Scoping trivy to the manifest file
        # alone would report only direct pins, which is precisely the blind
        # spot #239 is about.
        return _execute(tool, TOOL_COMMANDS[tool](str(repo_path)), repo_path, run)

    relevant = paths_for_tool(tool, paths)
    if not relevant:
        raise ToolNotApplicable(f"no files in this diff are scannable by {tool}")

    if strategy == PACKAGE:
        packages = go_packages_for(relevant)
        if not packages:
            raise ToolNotApplicable("no Go files changed in this diff")
        cmd = ["gosec", "-fmt=json", "-quiet", *packages]
        return _execute(tool, cmd, repo_path, run)

    absolute = [str(repo_path / p) for p in relevant]

    if strategy == PER_FILE:
        reports = []
        for abs_path in absolute:
            reports.append(_execute(tool, TOOL_COMMANDS[tool](abs_path), repo_path, run))
        return _merge_reports(reports)

    # MULTI_PATH: the command builder produces one trailing path; replace it
    # with the full list rather than rebuilding each tool's flags here.
    base = TOOL_COMMANDS[tool](str(repo_path))
    if tool == "checkov":
        # checkov's -d takes a directory; -f takes files and repeats.
        cmd = [c for c in base if c not in ("-d", str(repo_path))]
        for abs_path in absolute:
            cmd.extend(["-f", abs_path])
    else:
        cmd = base[:-1] + absolute
    return _execute(tool, cmd, repo_path, run)


# Scanner CLIs colourise their own error output. That markup is meaningless
# once the text lands in a scan record or a PR comment, and it makes the
# message hard to read wherever it surfaces.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# (#253) Exit codes that mean "I ran". Anything else means the tool broke,
# and a broken tool must never be reported as a clean result.
#
# Most entries are {0} on purpose. The flags already in TOOL_COMMANDS (
# gitleaks' `--exit-code 0`, checkov's and tfsec's `--soft-fail`) exist
# precisely so *findings* don't produce a nonzero exit. That makes nonzero
# mean "I broke" and nothing else, which is the signal this table preserves.
#
# semgrep is the exception: it documents 1 as "findings were reported", and
# we do not pass a flag to suppress that.
TOOL_SUCCESS_EXIT_CODES = {
    "semgrep": {0, 1},
    "semgrep-llm": {0, 1},
    "gitleaks": {0},        # --exit-code 0
    "noseyparker": {0},
    "trivy": {0},
    "trivy-license": {0},
    "gosec": {0},
    "checkov": {0},         # --soft-fail
    "tfsec": {0},           # --soft-fail
}


def _execute(tool: str, cmd: list[str], repo_path: Path, run: ScanRunContext) -> dict | list:
    """Run one tool invocation and fold what it says about itself into ``run``.

    ``run`` is a required parameter rather than ambient state (#229): every
    caller below is inside a run, and a stand-in that forgets it fails here,
    loudly, instead of silently scanning with a shared cache and recording no
    health.
    """
    cwd = str(repo_path) if tool == "gosec" else None
    env = run.env
    cmd = _isolation_flags(tool, cmd, run)

    if tool == "modelscan":
        return _run_modelscan(cmd, run, env=env)

    if tool == "gitleaks":
        return _run_gitleaks(cmd, cwd, run, env=env)

    if tool == "noseyparker":
        return _run_noseyparker(cmd, cwd, run, env=env)

    # cmd is the caller's fixed per-tool argv (see the scanner command
    # builders above), no shell.
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=env)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit

    # (#253) Check this BEFORE falling through to the empty-stdout defaults
    # below. A tool that dies writes nothing to stdout, and "nothing on
    # stdout" was previously indistinguishable from "scanned everything,
    # found nothing"; so a crashed scanner reported a clean pass. Observed
    # for real: gitleaks exiting 1 with
    #   FTL Report path is not writable: /dev/stdout
    # on a file containing a live-format AWS key, surfacing as [].
    #
    # ToolExecutionError already routes to tools_failed, which already
    # renders as "not fully scanned"; the signal just never reached it.
    allowed = TOOL_SUCCESS_EXIT_CODES.get(tool)
    if allowed is not None and proc.returncode not in allowed:
        # stderr's tail, not the whole stream: enough to diagnose, bounded so
        # a tool that dumps megabytes can't fill the scan record.
        detail = _strip_ansi(proc.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "no stderr"
        raise ToolExecutionError(f"{tool} exited {proc.returncode}: {tail[:300]}")

    # (#229) The run survived its exit-code check, so anything it complained
    # about on stderr is a *warning*: it kept going and produced a report,
    # but part of what it was asked to do may not have happened. #253 taught
    # this codebase to stop reading a crash as a clean pass; this is the same
    # lesson one notch quieter, where the tool did not crash and the only
    # evidence is a line it wrote on the way past.
    _note_stderr(tool, proc.stderr, run.health)

    # checkov's JSON shape depends on how many IaC frameworks it found files
    # for in the target repo: a dict for a single framework, a list of
    # per-framework dicts when it spans more than one; parsers.parse_checkov
    # normalizes both, so its empty/error default here is a dict (the more
    # common single-framework case) rather than picking one shape and being
    # wrong half the time.
    dict_default_tools = ("semgrep", "trivy", "trivy-license", "gosec", "tfsec", "checkov")
    stdout = proc.stdout.strip()
    if not stdout:
        # The empty defaults below are kept (parsers downstream expect a
        # shape, not an exception) but they are a *fallback*, not a result.
        # A tool that exits 0 and writes nothing has told us nothing, and
        # "nothing" has been read as "clean" twice in this file's history
        # already (#253, #229). Record it so it cannot be the third.
        run.health.degrade(
            f"{tool} exited successfully but wrote no report, so there were no results to read"
        )
        return {} if tool in dict_default_tools else []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        run.health.degrade(
            f"{tool} produced output that is not valid JSON, so its findings could not be read"
        )
        return {} if tool in dict_default_tools else []
