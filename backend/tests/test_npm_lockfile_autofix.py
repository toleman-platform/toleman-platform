"""Tests for app.core.npm_lockfile_autofix -- real npm/yarn/pnpm lockfile
regeneration for npm-ecosystem Fix Plan packages (#247 follow-up).

No real network clone or package-manager install runs here: `clone_repo`
and `_run_pm_command` are mocked at the module boundary, same as
test_autofix.py mocks GitHub for `_commit_files_and_open_pr`. What's under
test is this module's OWN logic -- which package manager gets picked,
what command shape each one gets, the env a subprocess actually receives,
and every failure being translated into a clean AutofixError rather than a
bare exception escaping. A real end-to-end npm install is exercised
manually (see the plan's Testing section), not in CI.
"""
import os
import subprocess

import pytest

import app.core.npm_lockfile_autofix as npm_lockfile_autofix
from app.core.autofix import AutofixError
from app.core.npm_lockfile_autofix import (
    _detect_lockfile,
    _majority_ref_and_dir,
    _run_pm_command,
    _safe_scan_id_suffix,
    _scrubbed_pm_env,
    _strip_untrusted_pm_config,
    _yarn_major,
    build_npm_patch_files,
)
from app.models.models import Target


def _target(**kwargs) -> Target:
    defaults = dict(id=1, workspace_id=1, name="t", repo_url="https://github.com/a/t")
    defaults.update(kwargs)
    return Target(**defaults)


# ---------------------------------------------------------------------------
# _majority_ref_and_dir / _detect_lockfile
# ---------------------------------------------------------------------------


def test_majority_ref_and_dir_picks_the_most_common_ref_and_directory():
    pairs = [
        ("main", "frontend/package-lock.json"),
        ("main", "frontend/package-lock.json"),
        ("main", "tools/yarn.lock"),
        ("feature-x", "package-lock.json"),
    ]
    ref, manifest_dir = _majority_ref_and_dir(pairs)
    assert ref == "main"
    assert manifest_dir == "frontend"


def test_majority_ref_and_dir_root_level_manifest_has_empty_dir():
    ref, manifest_dir = _majority_ref_and_dir([("main", "package-lock.json")])
    assert ref == "main"
    assert manifest_dir == ""


def test_detect_lockfile_prefers_npm_then_pnpm_then_yarn(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "yarn.lock").write_text("")
    assert _detect_lockfile(tmp_path) == "package-lock.json"


def test_detect_lockfile_none_when_nothing_present(tmp_path):
    assert _detect_lockfile(tmp_path) is None


# ---------------------------------------------------------------------------
# _scrubbed_pm_env
# ---------------------------------------------------------------------------


def test_scrubbed_pm_env_excludes_ambient_secrets(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://should-not-leak")
    monkeypatch.setenv("WORKSPACE_API_KEY", "super-secret")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setenv("HOME", "/home/toleman")

    env = _scrubbed_pm_env()

    assert "DATABASE_URL" not in env
    assert "WORKSPACE_API_KEY" not in env
    assert env["PATH"] == "/usr/local/bin:/usr/bin"
    assert env["HOME"] == "/home/toleman"


def test_scrubbed_pm_env_merges_extra_overrides():
    env = _scrubbed_pm_env({"YARN_ENABLE_SCRIPTS": "false"})
    assert env["YARN_ENABLE_SCRIPTS"] == "false"


def test_scrubbed_pm_env_disables_yarn_path_by_default():
    assert _scrubbed_pm_env()["YARN_IGNORE_PATH"] == "1"


# ---------------------------------------------------------------------------
# _safe_scan_id_suffix / _strip_untrusted_pm_config
# ---------------------------------------------------------------------------


def test_safe_scan_id_suffix_encodes_scoped_package_names():
    """A scoped package like @scope/name contains a "/" -- clone_repo
    inserts scan_id directly into a destination path with no intermediate
    directory creation, so an unencoded "/" here would break the clone."""
    suffix = _safe_scan_id_suffix("@scope/name")
    assert "/" not in suffix
    assert suffix == "-scope-name"


def test_safe_scan_id_suffix_leaves_plain_names_untouched():
    assert _safe_scan_id_suffix("axios") == "axios"


def test_strip_untrusted_pm_config_removes_files_at_every_level(tmp_path):
    manifest_dir = tmp_path / "frontend"
    manifest_dir.mkdir()
    (tmp_path / ".npmrc").write_text("registry=https://evil.example\n")
    (manifest_dir / ".yarnrc.yml").write_text("yarnPath: ./evil.js\n")
    (manifest_dir / ".yarnrc").write_text("yarn-path ./evil\n")

    _strip_untrusted_pm_config(tmp_path, manifest_dir)

    assert not (tmp_path / ".npmrc").exists()
    assert not (manifest_dir / ".yarnrc.yml").exists()
    assert not (manifest_dir / ".yarnrc").exists()


def test_strip_untrusted_pm_config_leaves_unrelated_files_alone(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    _strip_untrusted_pm_config(tmp_path, tmp_path)
    assert (tmp_path / "package.json").exists()


# ---------------------------------------------------------------------------
# _run_pm_command
# ---------------------------------------------------------------------------


def test_run_pm_command_returns_stdout_on_success(monkeypatch, tmp_path):
    def fake_run(cmd, cwd, capture_output, text, timeout, env):
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = _run_pm_command(["npm", "--version"], cwd=tmp_path, timeout=5, env={})
    assert out == "ok\n"


def test_run_pm_command_missing_binary_raises_clean_autofix_error(monkeypatch, tmp_path):
    def fake_run(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(AutofixError, match="not installed"):
        _run_pm_command(["npm", "--version"], cwd=tmp_path, timeout=5, env={})


def test_run_pm_command_timeout_raises_clean_autofix_error(monkeypatch, tmp_path):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["npm"], timeout=5)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(AutofixError, match="timed out"):
        _run_pm_command(["npm", "install"], cwd=tmp_path, timeout=5, env={})


def test_run_pm_command_nonzero_exit_raises_with_stderr_tail(monkeypatch, tmp_path):
    def fake_run(*a, **k):
        return subprocess.CompletedProcess(["npm"], 1, stdout="", stderr="npm ERR! 404 Not Found - GET registry")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(AutofixError, match="404 Not Found"):
        _run_pm_command(["npm", "install"], cwd=tmp_path, timeout=5, env={})


# ---------------------------------------------------------------------------
# _yarn_major
# ---------------------------------------------------------------------------


def test_yarn_major_parses_classic_version(monkeypatch, tmp_path):
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", lambda *a, **k: "1.22.22\n")
    assert _yarn_major(tmp_path, {}) == "1"


def test_yarn_major_parses_berry_version(monkeypatch, tmp_path):
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", lambda *a, **k: "4.5.0\n")
    assert _yarn_major(tmp_path, {}) == "4"


def test_yarn_major_defaults_to_classic_on_probe_failure(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise AutofixError("yarn is not installed on this deployment")

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", boom)
    assert _yarn_major(tmp_path, {}) == "1"


# ---------------------------------------------------------------------------
# build_npm_patch_files
# ---------------------------------------------------------------------------


def _plan(package="axios", upgrade_to="1.7.4") -> dict:
    return {"package": package, "ecosystem": "npm", "upgrade_to": upgrade_to, "fixes": [], "unresolved": []}


def _stub_clone(monkeypatch, clone_dir, package_json='{"dependencies":{}}', lockfile_name="package-lock.json", lockfile_content="{}"):
    """Points npm_lockfile_autofix.clone_repo at a fake, pre-populated
    checkout instead of a real network clone, and skips real GitHub token
    resolution -- both irrelevant to what this module itself decides."""
    (clone_dir / "package.json").write_text(package_json)
    (clone_dir / lockfile_name).write_text(lockfile_content)
    monkeypatch.setattr(npm_lockfile_autofix, "clone_repo", lambda *a, **k: clone_dir)
    monkeypatch.setattr(npm_lockfile_autofix, "resolve_github_token", lambda *a, **k: "tok")
    monkeypatch.setattr(npm_lockfile_autofix, "repo_slug_from_url", lambda *a, **k: "a/t")


def test_build_npm_patch_files_encodes_scoped_package_name_in_scan_id(monkeypatch, tmp_path):
    target = _target()
    captured = {}

    def fake_clone_repo(repo_url, branch, github_token, scan_id):
        captured["scan_id"] = scan_id
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "package-lock.json").write_text("{}")
        return tmp_path

    monkeypatch.setattr(npm_lockfile_autofix, "clone_repo", fake_clone_repo)
    monkeypatch.setattr(npm_lockfile_autofix, "resolve_github_token", lambda *a, **k: "tok")
    monkeypatch.setattr(npm_lockfile_autofix, "repo_slug_from_url", lambda *a, **k: "a/t")
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", lambda *a, **k: "")

    build_npm_patch_files(None, target, _plan(package="@scope/name"), pairs=[("main", "package-lock.json")])

    assert "/" not in captured["scan_id"]


def test_build_npm_patch_files_no_lockfile_pairs_raises(monkeypatch):
    target = _target()
    with pytest.raises(AutofixError, match="could not locate a lockfile"):
        build_npm_patch_files(None, target, _plan(), pairs=[("main", "requirements.txt")])


def test_build_npm_patch_files_runs_npm_install_lockfile_only(monkeypatch, tmp_path):
    target = _target()
    _stub_clone(monkeypatch, tmp_path)
    captured = {}

    def fake_run(cmd, cwd, timeout, env):
        captured["cmd"] = cmd
        captured["env"] = env
        # Simulate the real bump: write the "after" content the way a real
        # `npm install --package-lock-only` would.
        (cwd / "package.json").write_text('{"dependencies":{"axios":"^1.7.4"}}')
        (cwd / "package-lock.json").write_text('{"version":"1.7.4"}')
        return ""

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    result = build_npm_patch_files(None, target, _plan(), pairs=[("main", "package-lock.json")])

    assert captured["cmd"][:2] == ["npm", "install"]
    assert "axios@1.7.4" in captured["cmd"]
    assert "--package-lock-only" in captured["cmd"]
    assert "--ignore-scripts" in captured["cmd"]

    assert result == [
        ("main", "package.json", '{"dependencies":{"axios":"^1.7.4"}}'),
        ("main", "package-lock.json", '{"version":"1.7.4"}'),
    ]


def test_build_npm_patch_files_strips_untrusted_config_before_any_pm_command(monkeypatch, tmp_path):
    """A repository-committed .yarnrc.yml can redirect a scoped package's
    registry or, via yarnPath, hand execution to a repo-committed binary.
    It must be gone before the FIRST package-manager invocation -- which
    for yarn is the version probe (_yarn_major), not just the later
    add/up command -- or the malicious file is still there to be read."""
    target = _target()
    _stub_clone(monkeypatch, tmp_path, lockfile_name="yarn.lock", lockfile_content="# yarn lockfile v1")
    (tmp_path / ".yarnrc.yml").write_text("yarnPath: ./evil.js\n")
    seen_configs = []

    def fake_run(cmd, cwd, timeout, env):
        seen_configs.append((cwd / ".yarnrc.yml").exists())
        return "1.22.22\n" if cmd[:2] == ["yarn", "--version"] else ""

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    build_npm_patch_files(None, target, _plan(), pairs=[("main", "yarn.lock")])

    assert seen_configs and not any(seen_configs)


def test_build_npm_patch_files_runs_pnpm_lockfile_only(monkeypatch, tmp_path):
    target = _target()
    _stub_clone(monkeypatch, tmp_path, lockfile_name="pnpm-lock.yaml", lockfile_content="lockfileVersion: '6.0'")
    captured = {}

    def fake_run(cmd, cwd, timeout, env):
        captured["cmd"] = cmd
        return ""

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    build_npm_patch_files(None, target, _plan(), pairs=[("main", "pnpm-lock.yaml")])

    assert captured["cmd"][:2] == ["pnpm", "add"]
    assert "--lockfile-only" in captured["cmd"]
    assert "--ignore-scripts" in captured["cmd"]


def test_build_npm_patch_files_yarn_berry_uses_update_lockfile_mode(monkeypatch, tmp_path):
    target = _target()
    _stub_clone(monkeypatch, tmp_path, lockfile_name="yarn.lock", lockfile_content="# yarn lockfile v1")
    captured = {}

    def fake_run(cmd, cwd, timeout, env):
        captured["cmd"] = cmd
        captured["env"] = env
        return ""

    monkeypatch.setattr(npm_lockfile_autofix, "_yarn_major", lambda *a, **k: "4")
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    build_npm_patch_files(None, target, _plan(), pairs=[("main", "yarn.lock")])

    assert captured["cmd"][:2] == ["yarn", "up"]
    assert "--mode=update-lockfile" in captured["cmd"]
    assert captured["env"]["YARN_ENABLE_SCRIPTS"] == "false"


def test_build_npm_patch_files_yarn_classic_uses_real_add(monkeypatch, tmp_path):
    target = _target()
    _stub_clone(monkeypatch, tmp_path, lockfile_name="yarn.lock", lockfile_content="# yarn lockfile v1")
    captured = {}

    def fake_run(cmd, cwd, timeout, env):
        captured["cmd"] = cmd
        return ""

    monkeypatch.setattr(npm_lockfile_autofix, "_yarn_major", lambda *a, **k: "1")
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    build_npm_patch_files(None, target, _plan(), pairs=[("main", "yarn.lock")])

    assert captured["cmd"] == ["yarn", "add", "axios@1.7.4", "--ignore-scripts"]


def test_build_npm_patch_files_monorepo_subdir_paths_are_prefixed(monkeypatch, tmp_path):
    target = _target()
    subdir = tmp_path / "frontend"
    subdir.mkdir()
    _stub_clone(monkeypatch, subdir)
    monkeypatch.setattr(npm_lockfile_autofix, "clone_repo", lambda *a, **k: tmp_path)
    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", lambda *a, **k: "")

    result = build_npm_patch_files(None, target, _plan(), pairs=[("main", "frontend/package-lock.json")])

    assert [r[1] for r in result] == ["frontend/package.json", "frontend/package-lock.json"]


def test_build_npm_patch_files_cleans_up_clone_dir_even_on_failure(monkeypatch, tmp_path):
    target = _target()
    _stub_clone(monkeypatch, tmp_path)

    def boom(*a, **k):
        raise AutofixError("npm failed (1): some registry error")

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", boom)

    with pytest.raises(AutofixError, match="registry error"):
        build_npm_patch_files(None, target, _plan(), pairs=[("main", "package-lock.json")])

    assert not tmp_path.exists()


def test_build_npm_patch_files_missing_result_files_raises(monkeypatch, tmp_path):
    """The package manager ran (exit 0) but somehow left no package.json --
    should never happen for a real tool, but must fail loudly rather than
    return a patch with missing content."""
    target = _target()
    _stub_clone(monkeypatch, tmp_path)

    def fake_run(cmd, cwd, timeout, env):
        os.remove(cwd / "package.json")
        return ""

    monkeypatch.setattr(npm_lockfile_autofix, "_run_pm_command", fake_run)

    with pytest.raises(AutofixError, match="did not produce"):
        build_npm_patch_files(None, target, _plan(), pairs=[("main", "package-lock.json")])
