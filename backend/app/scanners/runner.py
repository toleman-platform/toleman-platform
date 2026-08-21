"""Native execution: clone target repo, run CLI security tools, return raw output.

MVP note: runs directly via subprocess (no container isolation yet). Architecture
review flagged this as a blocker before mass-scale/multi-tenant rollout — fine for
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
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from app.core.config import settings

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
    "semgrep": lambda path: ["semgrep", "scan", "--config=auto", "--json", "--quiet", path],
    # Issue #189: the LLM ruleset runs as its own tool rather than as an extra
    # --config on the semgrep entry above. Findings then carry tool
    # "semgrep-llm", so per-tool coverage reporting, usage assignment (#75)
    # and triage can all distinguish "the registry's generic rules" from
    # "Rikugan's LLM rules" instead of merging them into one bucket. Same
    # reasoning as trivy vs trivy-license already being separate entries.
    "semgrep-llm": lambda path: [
        "semgrep", "scan", f"--config={LLM_RULES_DIR}", "--json", "--quiet", path
    ],
    # `--report-path` was /dev/stdout until #253. That is not portable: where
    # /dev/stdout isn't writable by the process, gitleaks aborts with
    # "Report path is not writable" *before scanning anything*, exits 1 and
    # writes nothing -- which used to read as "no secrets found". The exit
    # code is now checked, and the report goes to a real temp file so the
    # failure doesn't happen in the first place. Same treatment as modelscan.
    # noseyparker (#255). Two-step by design: `scan` writes into a datastore,
    # `report` renders it. run_tool substitutes a real temp datastore for the
    # placeholder, same pattern as modelscan's report file.
    "noseyparker": lambda path: ["noseyparker", "scan", "--datastore", NOSEYPARKER_DATASTORE_PLACEHOLDER, path],
    "gitleaks": lambda path: ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", GITLEAKS_REPORT_PLACEHOLDER, "--no-git", "--exit-code", "0"],
    "trivy": lambda path: ["trivy", "fs", "--format", "json", "--quiet", path],
    "trivy-license": lambda path: ["trivy", "fs", "--scanners", "license", "--format", "json", "--quiet", path],
    "trivy-sbom": lambda path: ["trivy", "fs", "--format", "cyclonedx", "--quiet", path],
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
    # not here -- see MODELSCAN_REPORT_PLACEHOLDER for why modelscan can't
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
MODELSCAN_REPORT_PLACEHOLDER = "__RIKUGAN_MODELSCAN_REPORT__"

# (#253) Same substitution for gitleaks -- see its TOOL_COMMANDS entry.
GITLEAKS_REPORT_PLACEHOLDER = "__RIKUGAN_GITLEAKS_REPORT__"

# (#255) noseyparker scans into a datastore, then reports out of it.
NOSEYPARKER_DATASTORE_PLACEHOLDER = "__RIKUGAN_NOSEYPARKER_DATASTORE__"


class ToolExecutionError(Exception):
    """A scanner failed to execute (as opposed to running fine and finding
    nothing). Raised where a tool's exit code genuinely means "I broke",
    so scan_tasks marks the Scan failed instead of recording an empty,
    successful-looking result -- a scan that silently reports zero findings
    because the tool crashed is a false all-clear.
    """


class RepoCloneError(Exception):
    """Raised for a repo_url/branch that fails validation before ever
    reaching subprocess. Deliberately NOT a subprocess.CalledProcessError
    subclass, and deliberately not retried by Celery (see
    app/tasks/scan_tasks.py RETRYABLE_EXCEPTIONS) -- bad input won't become
    good input on retry.
    """


class ToolNotApplicable(Exception):
    """Diff-scoped scanning (#243) left this tool with nothing to examine --
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
    pass validation, so it can never reach the subprocess call at all --
    independent of (and in addition to) the "--" positional separator below.
    """
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RepoCloneError(f"repo_url must be an https:// URL, got: {repo_url!r}")
    if parsed.netloc not in ALLOWED_CLONE_HOSTS:
        raise RepoCloneError(
            f"repo_url host {parsed.netloc!r} is not supported (allowed: {sorted(ALLOWED_CLONE_HOSTS)})"
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


def clone_repo(repo_url: str, branch: str, github_token: str = "", scan_id: int | str | None = None) -> Path:
    """Clone repo_url@branch into a scan-scoped workdir.

    The destination is keyed by repo name AND a unique suffix (the caller's
    scan_id when available, otherwise a fresh UUID) so that two concurrent
    scans of the same target -- or of different targets that happen to
    share a repo name -- never resolve to the same directory. Previously
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
      verbatim -- if the token were on the command line (e.g. via `git -c
      http.extraHeader=...` as an argv entry), it would leak into any log
      line or API response that ever surfaces str(exc) for a failed clone.
    - The header uses HTTP Basic (base64 "x-access-token:<token>"), not
      Bearer. get_github_token() (app/core/github.py) can return either a
      GITHUB_TOKEN PAT (ghp_/github_pat_) or, as a fallback, whatever `gh
      auth token` has cached -- which for a `gh auth login` session is an
      OAuth App user-to-server token (gho_). Verified live: gho_ tokens are
      accepted by GitHub's REST API and by git-over-http with Basic auth
      (in the x-access-token:<token> form), but git's http backend rejects
      them under `Authorization: Bearer <token>` with "could not read
      Username for 'https://github.com/'" (exit 128) -- Bearer only works
      for ghp_/github_pat_ there. Basic works for all three token shapes,
      so it's used unconditionally rather than branching on token prefix.
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
    if github_token:
        basic = base64.b64encode(f"x-access-token:{github_token}".encode()).decode()
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.extraheader"
        env["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {basic}"

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
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
        # will not change -- see _classify_clone_stderr for why this matters
        # beyond tidiness.
        permanent = _classify_clone_stderr(exc.stderr or "")
        if permanent:
            raise RepoCloneError(permanent) from exc
        raise
    return dest


# Substrings git prints for causes that are permanent -- retrying cannot fix
# them -- paired with the message an operator can actually act on.
#
# Why this exists: clone_error_message used to reduce every failure to
# "git clone failed (exit code 128)". That was safe (it never echoes argv or
# a token) but it threw away the diagnosis along with the danger. A real
# deployment sat in a retry loop against two private repos with no
# credentials configured, and the only clue in the logs was the exit code --
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


def _classify_clone_stderr(stderr: str) -> str | None:
    """Actionable message for a permanently-failing clone, or None when the
    cause looks transient (network blip, remote hangup) and a retry is
    worth attempting.

    Returns only messages composed here -- never the raw stderr -- so a path,
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
    CalledProcessError that used to mean the full argv -- including the
    embedded GitHub token, before this fix. The token can no longer reach
    argv (see clone_repo), but this still avoids echoing raw subprocess
    argv/paths back to callers as a matter of course.
    """
    if isinstance(exc, RepoCloneError):
        return str(exc)
    if isinstance(exc, subprocess.CalledProcessError):
        # Prefer a cause the reader can act on. _classify_clone_stderr only
        # ever returns strings composed in this module, so this stays free of
        # raw argv/paths/tokens -- the exit code alone was safe but useless.
        classified = _classify_clone_stderr(exc.stderr or "")
        if classified:
            return classified
        return f"git clone failed (exit code {exc.returncode})"
    return str(exc)


def normalize_file_path(file_path: str, repo_path: Path) -> str:
    """Strip the scan-scoped clone directory prefix so file_path is relative
    to the repo root, e.g. "vulnerability/idor/idor.go" not
    "/tmp/rikugan-scans/govwa-<scan-id>/vulnerability/idor/idor.go".

    This matters beyond cosmetics: compute_dedup_hash includes file_path, and
    since clone_repo (above) gives every scan its own unique directory name
    for isolation, an un-normalized absolute path made the dedup hash change
    on every single scan -- silently defeating dedup entirely (every rescan
    created a new Finding instead of updating last_seen on the existing one).
    Call this on every parsed finding's file_path before hashing/persisting.
    """
    if not file_path:
        return file_path
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        # Already relative (some tools report paths relative to the scan
        # root they were invoked against) -- nothing to strip.
        return file_path


def _validate_scan_url(url: str) -> None:
    """Defense in depth for run_nuclei below: the caller (app.core.api_scan_targets)
    already builds these URLs from a Target's own operator-configured
    api_base_url plus its own persisted ApiEndpoint routes, and already
    confirms every URL's host matches api_base_url's host -- so nothing
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

    Safety posture (issue #72 -- this is ACTIVE scanning against real
    network endpoints, unlike every other scanner in this module which only
    reads a git checkout):
      - Every URL is re-validated here (see _validate_scan_url) even though
        the caller already built/validated them, so this function is safe
        to call directly.
      - URLs are written to a temp file and passed via `-l <file>`, never
        joined into a shell string or passed as a single argv blob --
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
        (an external network dependency this platform doesn't control) --
        keeps scanning self-contained to what this process directly
        observes.
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
        if settings.nuclei_exclude_tags:
            cmd += ["-etags", settings.nuclei_exclude_tags]
        proc = subprocess.run(
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


def _run_noseyparker(cmd: list[str], cwd: str | None) -> list:
    """Scan into a temp datastore, then report out of it (#255).

    Unlike every other tool here, noseyparker's scan step writes no findings
    to stdout -- the datastore is the output, and `report` renders it. Both
    steps' exit codes are checked: a scan that died leaves an empty datastore,
    and an empty datastore renders as `[]`, which is the false all-clear #253
    was about arriving through a new door.
    """
    datastore = Path(tempfile.mkdtemp(prefix="rikugan-np-")) / "datastore"
    scan_cmd = [str(datastore) if c == NOSEYPARKER_DATASTORE_PLACEHOLDER else c for c in cmd]
    try:
        proc = subprocess.run(scan_cmd, capture_output=True, text=True, cwd=cwd)
        if proc.returncode != 0:
            detail = _strip_ansi(proc.stderr or "").strip().splitlines()
            raise ToolExecutionError(
                f"noseyparker scan exited {proc.returncode}: {(detail[-1] if detail else 'no stderr')[:300]}"
            )
        report = subprocess.run(
            ["noseyparker", "report", "--datastore", str(datastore), "--format", "json"],
            capture_output=True, text=True, cwd=cwd,
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


def _run_gitleaks(cmd: list[str], cwd: str | None) -> list:
    """Run gitleaks with its report going to a real file (#253).

    Substitutes GITLEAKS_REPORT_PLACEHOLDER for a temp path, then reads the
    report back. `--exit-code 0` means findings do not affect the exit
    status, so any nonzero exit here is a genuine execution failure and
    becomes a ToolExecutionError rather than an empty, clean-looking result.
    """
    report_path = Path(tempfile.mkdtemp(prefix="rikugan-gitleaks-")) / "report.json"
    resolved = [str(report_path) if c == GITLEAKS_REPORT_PLACEHOLDER else c for c in cmd]
    try:
        proc = subprocess.run(resolved, capture_output=True, text=True, cwd=cwd)
        if proc.returncode != 0:
            detail = _strip_ansi(proc.stderr or "").strip().splitlines()
            tail = detail[-1] if detail else "no stderr"
            raise ToolExecutionError(f"gitleaks exited {proc.returncode}: {tail[:300]}")
        if not report_path.exists():
            # Exited 0 but wrote nothing. Do not assume "clean" -- gitleaks
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


def _run_modelscan(cmd: list[str]) -> dict:
    """Run modelscan with its report directed at a temp file and read it back
    (issue #186). See MODELSCAN_REPORT_PLACEHOLDER for why stdout is unusable.

    Exit codes are modelscan's own and do NOT follow the usual convention:
        0  scan ok, nothing found
        1  scan ok, *vulnerabilities found*   <- success, not failure
        2  modelscan itself errored
        3  no supported files provided
        4  invalid CLI options
    Only 2 and 4 are real failures. Treating 1 as an error would discard
    exactly the findings this tool exists to produce -- the same hazard
    checkov/tfsec avoid above with --soft-fail, which modelscan has no
    equivalent of.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "modelscan-report.json"
        resolved = [str(report_path) if part == MODELSCAN_REPORT_PLACEHOLDER else part for part in cmd]
        proc = subprocess.run(resolved, capture_output=True, text=True)

        if proc.returncode in (2, 4):
            raise ToolExecutionError(f"modelscan failed (exit {proc.returncode})")

        if not report_path.exists():
            # Exit 3 (nothing supported to scan) legitimately writes no
            # report. That is a clean, successful scan of a repo with no
            # model files -- not an error, and not a silent skip.
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
#                it -- the honest scoping question is *whether a manifest
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
    "trivy-sbom": MANIFEST,
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
    about. An empty result means "nothing here for this tool" -- the caller
    must record that as *skipped*, never as a clean run."""
    exts = TOOL_EXTENSIONS.get(tool)
    if exts is None:
        return list(paths)
    return [p for p in paths if p.lower().endswith(exts)]


def go_packages_for(paths: list[str]) -> list[str]:
    """Changed .go files -> the package directories gosec should walk.

    A file at the repo root maps to "." (that package only), never "./..."
    -- the recursive form would walk the entire module while the scan still
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
    """
    if tool not in TOOL_COMMANDS:
        raise ValueError(f"unsupported tool: {tool}")

    if paths is not None:
        return _run_tool_scoped(tool, repo_path, paths)

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
        # tree -- scan the whole checkout. Scoping trivy to the manifest file
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
# Most entries are {0} on purpose. The flags already in TOOL_COMMANDS --
# gitleaks' `--exit-code 0`, checkov's and tfsec's `--soft-fail` -- exist
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
    "trivy-sbom": {0},
    "gosec": {0},
    "checkov": {0},         # --soft-fail
    "tfsec": {0},           # --soft-fail
}


def _execute(tool: str, cmd: list[str], repo_path: Path) -> dict | list:
    cwd = str(repo_path) if tool == "gosec" else None

    if tool == "modelscan":
        return _run_modelscan(cmd)

    if tool == "gitleaks":
        return _run_gitleaks(cmd, cwd)

    if tool == "noseyparker":
        return _run_noseyparker(cmd, cwd)

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)

    # (#253) Check this BEFORE falling through to the empty-stdout defaults
    # below. A tool that dies writes nothing to stdout, and "nothing on
    # stdout" was previously indistinguishable from "scanned everything,
    # found nothing" -- so a crashed scanner reported a clean pass. Observed
    # for real: gitleaks exiting 1 with
    #   FTL Report path is not writable: /dev/stdout
    # on a file containing a live-format AWS key, surfacing as [].
    #
    # ToolExecutionError already routes to tools_failed, which already
    # renders as "not fully scanned" -- the signal just never reached it.
    allowed = TOOL_SUCCESS_EXIT_CODES.get(tool)
    if allowed is not None and proc.returncode not in allowed:
        # stderr's tail, not the whole stream: enough to diagnose, bounded so
        # a tool that dumps megabytes can't fill the scan record.
        detail = _strip_ansi(proc.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "no stderr"
        raise ToolExecutionError(f"{tool} exited {proc.returncode}: {tail[:300]}")

    # checkov's JSON shape depends on how many IaC frameworks it found files
    # for in the target repo: a dict for a single framework, a list of
    # per-framework dicts when it spans more than one -- parsers.parse_checkov
    # normalizes both, so its empty/error default here is a dict (the more
    # common single-framework case) rather than picking one shape and being
    # wrong half the time.
    dict_default_tools = ("semgrep", "trivy", "trivy-license", "trivy-sbom", "gosec", "tfsec", "checkov")
    stdout = proc.stdout.strip()
    if not stdout:
        return {} if tool in dict_default_tools else []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {} if tool in dict_default_tools else []
