"""Real npm/yarn/pnpm lockfile regeneration for the Fix Plan's "Raise PR"
action (#247 follow-up), for the ecosystem app.core.remediation_autofix's
regex manifest bumpers cannot handle at all: every Node finding's
`Finding.file_path` (set by app.scanners.parsers.parse_trivy from trivy's
scan Target) is a LOCKFILE, not `package.json` -- and
`autofix._MANIFEST_BUMPERS` deliberately has no lockfile entry, because a
hand-edited hash-bearing lockfile produces a corrupt install. A text-only
edit to `package.json` alone would be wrong too: `npm ci`/equivalent
installs exactly what the lockfile pins, ignoring `package.json`'s ranges,
so bumping just the manifest silently changes nothing that actually gets
installed.

The only correct fix is to run the real package manager against a real
checkout and let it regenerate the lockfile with real hashes. This module
does exactly that -- clone, bump, read the result back into memory, clean
up -- and hands the two changed files back to
`remediation_autofix.raise_package_fix_pr`, which commits them through the
existing GitHub Contents API path (`autofix._commit_files_and_open_pr`)
exactly like every other Fix Plan write. No new push mechanism, no new
DB tables: this only replaces HOW the two files' new content is produced.

Three package managers, three different levels of safety:

  * npm  (`npm install <pkg>@<version> --package-lock-only`) and
  * pnpm (`pnpm add <pkg>@<version> --lockfile-only`)
    never touch `node_modules` at all -- no dependency is ever extracted,
    so no lifecycle script can run regardless of `--ignore-scripts`.
  * yarn berry (`yarn up <pkg>@<version> --mode=update-lockfile`) has the
    same lockfile-only property.
  * yarn classic (v1) has no lockfile-only mode upstream. The only way to
    regenerate its lockfile is a real `yarn add`, which does extract
    `node_modules` -- `--ignore-scripts` disables lifecycle scripts, it
    does not avoid the install. This is the one path here that accepts
    real (mitigated, not eliminated) risk from installing third-party
    code; `node_modules` is discarded with the rest of the clone and only
    the two text files are ever read back.

Every subprocess here runs with `_scrubbed_pm_env()` -- a minimal,
freshly-built env (PATH/HOME/LANG only, plus yarn berry's own script-
disable var), never the ambient `os.environ` app.scanners.runner's
`_isolated_run` passes to scanner subprocesses. This process needs no DB
URL, Redis URL, session secret, or GitHub token (the clone's own auth
already happened via git's `GIT_CONFIG_*` env, scoped to that one `git`
invocation, not inherited here) -- so none of it is handed to a package
manager that is, by design, about to run untrusted third-party install
logic. `settings.npm_install_timeout_seconds` bounds every invocation
below, mirroring `runner.run_nuclei`'s `timeout=` -- the one existing
subprocess in this codebase with a bound today.
"""
import logging
import os
import shutil
import subprocess
from pathlib import Path

from sqlmodel import Session

from app.core.autofix import AutofixError
from app.core.config import settings
from app.core.github import repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.models.models import Target
from app.scanners.runner import clone_repo

logger = logging.getLogger(__name__)

# OSV's exact ecosystem string for the npm registry (confirmed against this
# codebase's own test fixtures, which use OSV's other ecosystem strings
# verbatim, e.g. "PyPI" -- see backend/tests/test_remediation.py). A set,
# not a bare string, so a second npm-family ecosystem string (there isn't
# one today) would be a one-line addition rather than a second comparison
# to keep in sync.
NPM_ECOSYSTEMS = {"npm"}

_LOCKFILE_BASENAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}

# How long the one quick `yarn --version` probe (deciding classic vs berry)
# may take -- independent of, and much shorter than, the real bump's own
# npm_install_timeout_seconds below.
_VERSION_PROBE_TIMEOUT_SECONDS = 30


def _majority_ref_and_dir(pairs: list[tuple[str, str]]) -> tuple[str, str]:
    """Given every `(ref, file_path)` pair a package's findings point at
    (already filtered to lockfile basenames), pick the ref and manifest
    directory most of them agree on -- same "commit to whichever ref most
    of the bumpable files matched" tiebreak
    `remediation_autofix.raise_package_fix_pr` already uses for its own
    `base_ref`, extended with one more field. The overwhelmingly common
    case is exactly one pair; this only matters for a monorepo where the
    same package's CVEs land in more than one subproject."""
    refs = [ref for ref, _ in pairs]
    base_ref = max(set(refs), key=refs.count)
    dirs = [str(Path(path).parent) for ref, path in pairs if ref == base_ref]
    dirs = ["" if d == "." else d for d in dirs]
    base_dir = max(set(dirs), key=dirs.count)
    return base_ref, base_dir


def _detect_lockfile(manifest_dir: Path) -> str | None:
    """Which lockfile actually exists on disk in the clone -- not which one
    the finding named, since that's already known to be right by
    construction (it's why we're here), but this is what decides which
    package manager's command shape to run."""
    for basename in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        if (manifest_dir / basename).exists():
            return basename
    return None


def _scrubbed_pm_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A minimal env for a package-manager subprocess -- see this module's
    docstring for why this is deliberately NOT `{**os.environ, ...}`."""
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}
    for key in ("LANG", "LC_ALL"):
        if key in os.environ:
            env[key] = os.environ[key]
    if extra:
        env.update(extra)
    return env


def _run_pm_command(cmd: list[str], cwd: Path, timeout: int, env: dict[str, str]) -> str:
    """Runs `cmd`, returning stdout on success. Raises AutofixError (never a
    bare subprocess/OSError) on timeout, non-zero exit, or a missing binary
    -- same failure-translation discipline app.scanners.runner uses for its
    own tool subprocesses (FileNotFoundError -> "not installed", a real
    exit code -> the tool's own stderr, never a raw traceback)."""
    tool = cmd[0]
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError as exc:
        raise AutofixError(f"{tool} is not installed on this deployment") from exc
    except subprocess.TimeoutExpired as exc:
        raise AutofixError(f"{tool} timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise AutofixError(f"{tool} failed ({result.returncode}): {result.stderr[-500:].strip()}")
    return result.stdout


def _yarn_major(manifest_dir: Path, env: dict[str, str]) -> str:
    """The major version corepack actually activates for this repo (it
    reads package.json's own `packageManager` field, when present, ahead
    of whatever default this deployment pinned in its Dockerfile) --
    determines whether to run the classic (v1) or berry (v2+) command
    shape below. A probe failure is treated as classic: it's the older,
    more conservative default, and a wrong guess here fails loudly on the
    next command rather than silently corrupting anything."""
    try:
        out = _run_pm_command(["yarn", "--version"], cwd=manifest_dir, timeout=_VERSION_PROBE_TIMEOUT_SECONDS, env=env)
    except AutofixError:
        return "1"
    return out.strip().split(".")[0] or "1"


def build_npm_patch_files(
    session: Session, target: Target, plan: dict, pairs: list[tuple[str, str]]
) -> list[tuple[str, str, str]]:
    """(ref, file_path, new_content) for `package.json` and whichever
    lockfile this package's target actually uses, with `plan["package"]`
    bumped to `plan["upgrade_to"]` by running the real package manager
    against a real clone. Returns exactly two entries on success, or
    raises AutofixError -- there is no partial/skip case the way the
    regex bumpers have one, since there's only ever one manifest dir to
    try per call.

    `pairs` is every `(ref, file_path)` this package's findings point at --
    computed once by the caller (remediation_autofix.build_package_patch_files,
    via find_package_finding_files) rather than re-derived here, both to
    avoid a second DB round trip and to avoid this module importing back
    into remediation_autofix (which imports this module) at all.
    """
    pairs = [(ref, file_path) for ref, file_path in pairs if Path(file_path).name in _LOCKFILE_BASENAMES]
    if not pairs:
        raise AutofixError(
            f"could not locate a lockfile for {plan['package']} in any manifest file "
            "this target's open findings point at."
        )
    ref, manifest_dir_rel = _majority_ref_and_dir(pairs)

    slug = repo_slug_from_url(target.repo_url)
    token = resolve_github_token(session, target.workspace_id, slug) or ""

    clone_dir = clone_repo(target.repo_url, branch=ref, github_token=token, scan_id=f"npmfix-{target.id}-{plan['package']}")
    try:
        manifest_dir = clone_dir / manifest_dir_rel if manifest_dir_rel else clone_dir
        lockfile_name = _detect_lockfile(manifest_dir)
        if lockfile_name is None:
            raise AutofixError(
                f"cloned {slug}@{ref} but found no package-lock.json/yarn.lock/pnpm-lock.yaml "
                f"under '{manifest_dir_rel or '.'}'"
            )

        package = plan["package"]
        version = plan["upgrade_to"]
        env = _scrubbed_pm_env()
        timeout = settings.npm_install_timeout_seconds

        if lockfile_name == "package-lock.json":
            _run_pm_command(
                ["npm", "install", f"{package}@{version}", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=manifest_dir, timeout=timeout, env=env,
            )
        elif lockfile_name == "pnpm-lock.yaml":
            _run_pm_command(
                ["pnpm", "add", f"{package}@{version}", "--lockfile-only", "--ignore-scripts"],
                cwd=manifest_dir, timeout=timeout, env=env,
            )
        else:  # yarn.lock
            if _yarn_major(manifest_dir, env) == "1":
                _run_pm_command(
                    ["yarn", "add", f"{package}@{version}", "--ignore-scripts"],
                    cwd=manifest_dir, timeout=timeout, env=env,
                )
            else:
                berry_env = _scrubbed_pm_env({"YARN_ENABLE_SCRIPTS": "false"})
                _run_pm_command(
                    ["yarn", "up", f"{package}@{version}", "--mode=update-lockfile"],
                    cwd=manifest_dir, timeout=timeout, env=berry_env,
                )

        package_json_path = manifest_dir / "package.json"
        lockfile_path = manifest_dir / lockfile_name
        if not package_json_path.exists() or not lockfile_path.exists():
            raise AutofixError(f"{package}@{version} bump did not produce a package.json/{lockfile_name} pair")

        rel_package_json = f"{manifest_dir_rel}/package.json" if manifest_dir_rel else "package.json"
        rel_lockfile = f"{manifest_dir_rel}/{lockfile_name}" if manifest_dir_rel else lockfile_name
        return [
            (ref, rel_package_json, package_json_path.read_text(encoding="utf-8")),
            (ref, rel_lockfile, lockfile_path.read_text(encoding="utf-8")),
        ]
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)
