"""Native execution: clone target repo, run CLI security tools, return raw output.

MVP note: runs directly via subprocess (no container isolation yet). Architecture
review flagged this as a blocker before mass-scale/multi-tenant rollout; fine for
single-user local/dev use, must move to ephemeral containers (K8s Job) before
that feature ships.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from app.core.config import settings
from app.core.scan_health import ScanHealth

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
      - `-duc` (disable update check) is the nuclei half of #229. nuclei
        keeps its template store in one shared directory and rewrites it in
        place when it decides an update is due. Two concurrent nuclei runs
        then have one process replacing the templates the other is loading,
        which is the same shape as the trivy DB race that made a repo with
        five live CVEs report clean: a process that loaded a half-written
        template set still exits 0, still emits valid JSONL, and simply
        finds less. With updates disabled no scan run mutates the shared
        store, so template refresh becomes an explicit ops step rather than
        something that fires mid-scan.
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
            "-duc",
            "-rate-limit", str(settings.nuclei_rate_limit),
            "-timeout", "5",
        ]
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


def _run_noseyparker(cmd: list[str], cwd: str | None, env: dict[str, str] | None = None) -> list:
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


def _run_gitleaks(cmd: list[str], cwd: str | None, env: dict[str, str] | None = None) -> list:
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


def _run_modelscan(cmd: list[str], env: dict[str, str] | None = None) -> dict:
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
# 1. Shared mutable tool state. Several bundled CLIs keep their working data
#    in one per-user directory and assume they are the only process in it:
#
#      trivy    $TRIVY_CACHE_DIR (default $HOME/.cache/trivy, or
#               $XDG_CACHE_HOME/trivy) holds the vulnerability DB. trivy
#               replaces that DB in place when it decides an update is due.
#               A second trivy reading it mid-replacement finishes happily:
#               exit 0, valid JSON, empty Vulnerabilities. That is exactly
#               what #229 reproduced -- six concurrent scans, one of which
#               reported a repo with five live CVEs as clean, while the
#               same command run alone a minute later found all five.
#      semgrep  --config=auto downloads the registry ruleset into
#               $XDG_CACHE_HOME/semgrep and rewrites its settings file on
#               every run; concurrent runs race the same files.
#      nuclei   see run_nuclei's `-duc` above; templates are handled there
#               because nuclei is invoked through its own function.
#
#    So every run gets a private cache directory, seeded from the shared one
#    by hardlink where the filesystem allows it (a hardlink is a snapshot:
#    an updater that replaces the shared file writes a new inode and leaves
#    this run's view intact, and it costs no disk and no download). trivy
#    additionally runs with --skip-db-update once seeded, so a scan process
#    can never be the thing that rewrites a DB some other scan is reading.
#
# 2. A zero-finding result being trusted unconditionally. Isolation makes
#    the race far less likely; it does not make an empty result *provable*.
#    So the run also collects evidence about itself -- DB freshness, the
#    warnings the tool wrote to stderr, whether it reported examining
#    anything at all -- into a ScanHealth, and app.core.ingestion refuses to
#    mitigate existing findings off a zero-finding run that is not
#    positively healthy. That is the same rule osv_malware.py already
#    applies with its None-vs-{} return; see app/core/scan_health.py.


@dataclass
class _RunContext:
    """State shared by every subprocess invocation within one tool run."""

    health: ScanHealth
    # Environment for the tool's subprocess. Empty means "inherit ours".
    env: dict[str, str] = field(default_factory=dict)
    # This run's private cache root, or None when isolation was not
    # applicable (the tool keeps no shared state) or could not be set up.
    cache_dir: Path | None = None
    # Whether the private cache was successfully populated from the shared
    # one. Governs whether trivy may be told --skip-db-update: telling it to
    # skip the update when it has no DB at all would turn every scan on a
    # cold cache into a hard failure.
    seeded: bool = False


# Why a ContextVar rather than threading two more parameters through
# _execute: _execute's (tool, cmd, repo_path) signature is what every
# scoping strategy above and every existing test double already uses, and a
# PER_FILE run calls it once per changed file -- the context belongs to the
# *run*, not to any one invocation. A ContextVar also keeps two runs sharing
# a worker process (a threaded Celery pool, the API threadpool) from seeing
# each other's cache directory, which is the entire point here.
_CURRENT_RUN: ContextVar["_RunContext | None"] = ContextVar("toleman_scan_run", default=None)

# Directory name holding per-run tool caches; see _run_cache_base for where
# it gets created.
TOOL_CACHE_DIRNAME = "toleman-tool-cache"

# Ceiling on the plain-copy seeding fallback. Hardlinking is the intended
# path and costs nothing; a real copy is only worth doing for a small cache.
# Without this bound a deployment whose scan cache and tool cache sit on
# different filesystems would copy a multi-hundred-megabyte trivy database
# on every single scan, which is a worse problem than the one being fixed.
MAX_COPY_SEED_BYTES = 64 * 1024 * 1024

# trivy writes this next to the DB it just installed.
TRIVY_DB_METADATA_PATH = "db/metadata.json"

# How far past trivy's own declared NextUpdate the DB has to be before this
# treats the run as suspect. NextUpdate passing is routine (trivy publishes
# every 6h and refreshes opportunistically); a DB days past it means the
# refresh has been failing, and vulnerabilities published since then simply
# cannot be found -- a zero-finding run against one is not evidence of a
# clean repo.
TRIVY_DB_STALE_GRACE_HOURS = 72

# Substrings a scanner writes to stderr when part of the work it was asked
# to do did not actually happen. Matched case-insensitively anywhere in the
# stream.
#
# Deliberately narrow. A scanner logs plenty of ordinary chatter, and a list
# that flags every run teaches operators that "suspect" means nothing, which
# is worse than not having the signal: the point is that a suspect run
# blocks auto-mitigation, and a signal nobody believes gets switched off.
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


def _trivy_shared_cache() -> Path:
    """Where trivy would keep its DB if we left it alone."""
    explicit = os.environ.get("TRIVY_CACHE_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "trivy"
    return Path.home() / ".cache" / "trivy"


def _semgrep_shared_cache() -> Path:
    """Where semgrep keeps the registry rules --config=auto downloads."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "semgrep"
    return Path.home() / ".cache" / "semgrep"


def _tree_size(path: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                continue
    return total


def _seed_cache(src: Path, dst: Path) -> bool:
    """Populate ``dst`` from ``src``, hardlinking rather than copying.

    A hardlink is a snapshot with no disk cost: an updater that replaces the
    shared file writes a new inode, and this run keeps seeing the complete
    old one. That is the property that makes isolation cheap enough to do on
    every scan.

    Best-effort by design. A run whose cache could not be seeded still runs;
    it just pays for a cold download (and, for trivy, does not get
    --skip-db-update). Returns whether ``dst`` ended up with any content.

    The plain-copy fallback deletes the partial tree first rather than
    merging into it: overwriting an already-hardlinked file with copy2 would
    write *through* the link into the shared cache, which is precisely the
    corruption this function exists to avoid.
    """
    if not src.is_dir():
        return False
    try:
        shutil.copytree(src, dst, copy_function=os.link, dirs_exist_ok=True)
    except (OSError, shutil.Error):
        # Almost always EXDEV: src and dst are on different filesystems.
        shutil.rmtree(dst, ignore_errors=True)
        if _tree_size(src) > MAX_COPY_SEED_BYTES:
            return False
        try:
            shutil.copytree(src, dst, dirs_exist_ok=True)
        except (OSError, shutil.Error):
            shutil.rmtree(dst, ignore_errors=True)
            return False
    try:
        return any(dst.iterdir())
    except OSError:
        return False


def _run_cache_base(shared: Path) -> Path:
    """Where a run's private cache is created, given the shared one.

    Adjacent to the shared cache by preference, because hardlink seeding only
    works within a single filesystem and settings.scan_workdir (/tmp by
    default) is routinely on a different one from $HOME/.cache -- on a tmpfs
    /tmp, "isolation" would quietly degrade into copying a multi-hundred-
    megabyte vulnerability database on every scan, or into no seeding at all.

    Falls back to scan_workdir when the shared cache's parent is not writable
    (a cache baked into a read-only image layer), where paying for a download
    is at least correct.
    """
    candidates = (
        shared.parent / TOOL_CACHE_DIRNAME,
        Path(settings.scan_workdir) / TOOL_CACHE_DIRNAME,
    )
    last_error: OSError | None = None
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError as exc:
            last_error = exc
    raise last_error if last_error else OSError("no writable tool-cache location")


def _isolate_trivy() -> tuple[dict[str, str], bool, Path]:
    shared = _trivy_shared_cache()
    private = Path(tempfile.mkdtemp(prefix="trivy-", dir=str(_run_cache_base(shared))))
    seeded = _seed_cache(shared / "db", private / "db")
    return {"TRIVY_CACHE_DIR": str(private)}, seeded, private


def _isolate_semgrep() -> tuple[dict[str, str], bool, Path]:
    # XDG_CACHE_HOME is a cache *root*, so semgrep's own subdirectory sits
    # under it; SEMGREP_SETTINGS_FILE is a file path and has to be named
    # separately, since semgrep rewrites that file on every run and two
    # concurrent runs otherwise race it.
    shared = _semgrep_shared_cache()
    private = Path(tempfile.mkdtemp(prefix="semgrep-", dir=str(_run_cache_base(shared))))
    (private / "semgrep").mkdir(parents=True, exist_ok=True)
    seeded = _seed_cache(shared, private / "semgrep")
    return {
        "XDG_CACHE_HOME": str(private),
        "SEMGREP_SETTINGS_FILE": str(private / "semgrep_settings.yml"),
    }, seeded, private


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
    """Give this run its own copy of ``tool``'s shared state, then remove it.

    Cleanup is unconditional: a private cache that outlives its run is just
    disk, and hardlinks mean removing it never touches the shared copy.
    """
    isolate = TOOL_CACHE_ISOLATION.get(tool)
    context = _RunContext(health=health)
    cache_root: Path | None = None
    if isolate is not None:
        try:
            overrides, seeded, cache_root = isolate()
            context.env = {**os.environ, **overrides}
            context.cache_dir = cache_root
            context.seeded = seeded
        except OSError as exc:
            # Falling back to the shared cache is worse than isolation but
            # better than failing the scan outright -- and the run is marked
            # suspect, so it cannot silently clear anything either way.
            if cache_root is not None:
                shutil.rmtree(cache_root, ignore_errors=True)
                cache_root = None
            context = _RunContext(health=health)
            health.degrade(
                f"could not isolate {tool}'s cache for this run ({exc.__class__.__name__}), "
                "so it shared mutable state with any concurrent scan"
            )
    token = _CURRENT_RUN.set(context)
    try:
        yield context
    finally:
        _CURRENT_RUN.reset(token)
        if cache_root is not None:
            shutil.rmtree(cache_root, ignore_errors=True)


def _isolation_flags(tool: str, cmd: list[str], run: "_RunContext | None") -> list[str]:
    """Per-tool argv additions that depend on the isolated cache.

    trivy only: with a seeded private DB there is nothing to update and no
    reason to let this process write one, so --skip-db-update makes the run
    deterministic and takes it out of the race entirely. Without a seeded DB
    the flag is omitted, because trivy refuses to scan with no database.
    """
    if run is None or not run.seeded:
        return cmd
    if tool in ("trivy", "trivy-license") and "--skip-db-update" not in cmd:
        # argv is ["trivy", "fs", ...]; the flag goes after the subcommand.
        return [*cmd[:2], "--skip-db-update", *cmd[2:]]
    return cmd


def _note_stderr(tool: str, stderr: str, health: ScanHealth) -> None:
    """Degrade the run for anything the tool said about not finishing."""
    text = _strip_ansi(stderr or "").lower()
    if not text:
        return
    for marker in SUSPECT_STDERR_MARKERS:
        if marker in text:
            health.degrade(f'{tool} warned "{marker}" while scanning, so its results may be incomplete')


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


def _assess_trivy_db(cache_dir: Path, health: ScanHealth) -> None:
    """Was there a usable vulnerability database behind this run?

    This is the signal that speaks directly to #229's reproduction. A trivy
    process that read a DB mid-replacement, or ran against one whose refresh
    has been failing for days, cannot support "this repository is clean".
    """
    metadata_path = cache_dir / TRIVY_DB_METADATA_PATH
    if not metadata_path.exists():
        health.degrade(
            "trivy ran without a vulnerability database, so it could not have found any CVE"
        )
        return
    try:
        metadata = json.loads(metadata_path.read_text())
    except (OSError, ValueError):
        health.degrade("trivy's vulnerability database metadata was unreadable")
        return
    if not isinstance(metadata, dict):
        health.degrade("trivy's vulnerability database metadata was unreadable")
        return
    next_update = _parse_trivy_timestamp(metadata.get("NextUpdate"))
    if next_update is None:
        health.degrade("trivy's vulnerability database does not say when it was last refreshed")
        return
    overdue_by = datetime.now(timezone.utc) - next_update
    if overdue_by > timedelta(hours=TRIVY_DB_STALE_GRACE_HOURS):
        health.degrade(
            f"trivy's vulnerability database is {overdue_by.days} day(s) past its own refresh "
            "deadline, so anything published since then cannot be found"
        )


def repo_has_dependency_manifest(repo_path: Path) -> bool:
    """Does this checkout contain anything trivy resolves dependencies from?

    Reuses MANIFEST_FILENAMES, the same list diff-scoping uses to decide
    whether a MANIFEST tool has anything to say about a PR. `.git` is
    pruned: a packfile is not a manifest and walking one is wasted work.
    """
    for _dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            if name in MANIFEST_FILENAMES or name.startswith("Dockerfile"):
                return True
    return False


def _assess_result(tool: str, repo_path: Path, raw: dict | list, run: "_RunContext") -> None:
    """Post-run checks that need the report and the checkout together."""
    if tool not in ("trivy", "trivy-license"):
        return

    trivy_cache = run.env.get("TRIVY_CACHE_DIR")
    if trivy_cache:
        _assess_trivy_db(Path(trivy_cache), run.health)

    # The zero-findings-against-a-non-empty-manifest heuristic. trivy emits
    # one Results entry per package source it resolved, independently of
    # whether anything in it was vulnerable -- so an empty Results list from
    # a repository that demonstrably has manifests means trivy resolved
    # nothing at all, which is a different statement from "resolved your
    # dependencies, none are vulnerable". Only the second one is a clean
    # result, and only the second one may clear existing findings.
    examined_something = isinstance(raw, dict) and bool(raw.get("Results"))
    if not examined_something and repo_has_dependency_manifest(repo_path):
        run.health.degrade(
            f"{tool} reported no package sources at all for a repository that contains "
            "dependency manifests, so it did not resolve this repository's dependencies"
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
        raw = _run_tool_inner(tool, repo_path, paths)
        _assess_result(tool, repo_path, raw, run)
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
    private trivy/semgrep cache. Only the health verdict is dropped, which
    is why any caller that mitigates findings has to use run_tool_checked
    instead.
    """
    return run_tool_checked(tool, repo_path, paths)[0]


def _run_tool_inner(tool: str, repo_path: Path, paths: list[str] | None) -> dict | list:
    if paths is not None:
        return _run_tool_scoped(tool, repo_path, paths)

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
    return _execute(tool, cmd, repo_path)


def _run_tool_scoped(tool: str, repo_path: Path, paths: list[str]) -> dict | list:
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
        return _execute(tool, TOOL_COMMANDS[tool](str(repo_path)), repo_path)

    relevant = paths_for_tool(tool, paths)
    if not relevant:
        raise ToolNotApplicable(f"no files in this diff are scannable by {tool}")

    if strategy == PACKAGE:
        packages = go_packages_for(relevant)
        if not packages:
            raise ToolNotApplicable("no Go files changed in this diff")
        cmd = ["gosec", "-fmt=json", "-quiet", *packages]
        return _execute(tool, cmd, repo_path)

    absolute = [str(repo_path / p) for p in relevant]

    if strategy == PER_FILE:
        reports = []
        for abs_path in absolute:
            reports.append(_execute(tool, TOOL_COMMANDS[tool](abs_path), repo_path))
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
    return _execute(tool, cmd, repo_path)


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


def _execute(tool: str, cmd: list[str], repo_path: Path) -> dict | list:
    cwd = str(repo_path) if tool == "gosec" else None

    # (#229) The per-run cache isolation and the health sink both live on the
    # ambient run context rather than in this signature; see _CURRENT_RUN for
    # why. `None` means nobody set one up (a direct _execute call in a test),
    # in which case this behaves exactly as it did before: inherited
    # environment, no health recorded.
    run = _CURRENT_RUN.get()
    env = run.env or None if run is not None else None
    cmd = _isolation_flags(tool, cmd, run)

    if tool == "modelscan":
        return _run_modelscan(cmd, env=env)

    if tool == "gitleaks":
        return _run_gitleaks(cmd, cwd, env=env)

    if tool == "noseyparker":
        return _run_noseyparker(cmd, cwd, env=env)

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
    if run is not None:
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
        return {} if tool in dict_default_tools else []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {} if tool in dict_default_tools else []
