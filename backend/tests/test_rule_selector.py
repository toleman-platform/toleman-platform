"""Tests for the pruned-registry cache and polyglot layering in
app.scanners.rule_selector.

These build a miniature fake semgrep-rules clone on disk rather than
cloning the real ~2000-file registry: what is under test is the pruning,
caching and invalidation logic, none of which depends on the registry's
actual rule content, and a real clone would make the suite depend on a
network fetch it cannot verify.

The cache tests all assert on observable *rebuild* behaviour (the output
file's own content changing, or not), not just on the cache_hit flag.
A flag can be set correctly while the expensive work still happens; the
whole point of the cache is that the work does not happen.
"""

import json
import os
from pathlib import Path
from unittest import mock

import yaml

from app.scanners import rule_selector as rs


def _write_registry(root: Path, language: str, folder: str, filename: str, rules: list[dict]) -> Path:
    path = root / language / folder / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"rules": rules}))
    return path


def _rule(rule_id: str, category: str = "security") -> dict:
    return {
        "id": rule_id,
        "message": rule_id,
        "severity": "WARNING",
        "languages": ["python"],
        "pattern": "eval(...)",
        "metadata": {"category": category},
    }


def _loaded_ids(config_path: str) -> set[str]:
    doc = yaml.safe_load(Path(config_path).read_text())
    return {r["id"] for r in doc["rules"]}


def test_only_security_rules_are_kept_and_ids_are_deduped(tmp_path):
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [
        _rule("py.lang.security.one"),
        _rule("py.lang.correctness.noise", category="correctness"),
    ])
    _write_registry(registry, "python", "flask", "b.yaml", [
        _rule("py.lang.security.one"),  # duplicate id across folders
        _rule("py.flask.security.two"),
    ])

    pruned = rs.build_registry_config("python", {"flask"}, str(tmp_path / "cache"), str(registry))

    assert pruned is not None
    assert pruned.rule_count == 2
    assert _loaded_ids(pruned.path) == {"py.lang.security.one", "py.flask.security.two"}


def test_missing_language_folder_returns_none_rather_than_failing(tmp_path):
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    # Callers fall back to the custom pack alone; a language the vendored
    # clone has no folder for must not be an error.
    assert rs.build_registry_config("ruby", set(), str(tmp_path / "cache"), str(registry)) is None


def test_second_build_reuses_the_cached_file_instead_of_rebuilding(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    first = rs.build_registry_config("python", set(), str(cache), str(registry))
    assert first is not None and first.cache_hit is False

    # Overwrite the built config with a sentinel. A genuine cache hit
    # leaves it alone; a rebuild would clobber it back to the real rules.
    Path(first.path).write_text(yaml.safe_dump({"rules": [_rule("sentinel.untouched")]}))

    second = rs.build_registry_config("python", set(), str(cache), str(registry))

    assert second is not None
    assert second.cache_hit is True
    assert second.rule_count == 1  # carried through from the sidecar metadata
    assert _loaded_ids(second.path) == {"sentinel.untouched"}


def test_force_rebuild_bypasses_the_cache(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    first = rs.build_registry_config("python", set(), str(cache), str(registry))
    Path(first.path).write_text(yaml.safe_dump({"rules": [_rule("sentinel.untouched")]}))

    rebuilt = rs.build_registry_config("python", set(), str(cache), str(registry), force_rebuild=True)

    assert rebuilt.cache_hit is False
    assert _loaded_ids(rebuilt.path) == {"py.one"}


def test_changed_registry_content_invalidates_the_cache(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    rule_file = _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    first = rs.build_registry_config("python", set(), str(cache), str(registry))
    assert first.cache_hit is False

    # Refreshing the vendored clone changes size and mtime; the stat
    # fingerprint must notice. mtime is bumped explicitly because a write
    # inside the same coarse filesystem timestamp would otherwise look
    # unchanged on the second-resolution stat this fingerprint uses.
    rule_file.write_text(yaml.safe_dump({"rules": [_rule("py.one"), _rule("py.two")]}))
    stat = rule_file.stat()
    os.utime(rule_file, (stat.st_atime + 10, stat.st_mtime + 10))

    second = rs.build_registry_config("python", set(), str(cache), str(registry))

    assert second.cache_hit is False
    assert _loaded_ids(second.path) == {"py.one", "py.two"}


def test_changed_technology_set_invalidates_the_cache(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    _write_registry(registry, "python", "flask", "b.yaml", [_rule("py.flask.two")])

    without_flask = rs.build_registry_config("python", set(), str(cache), str(registry))
    assert _loaded_ids(without_flask.path) == {"py.one"}

    # Detecting a framework the previous run did not see must widen the
    # pruned config, not hand back the narrower cached one.
    with_flask = rs.build_registry_config("python", {"flask"}, str(cache), str(registry))

    assert with_flask.cache_hit is False
    assert _loaded_ids(with_flask.path) == {"py.one", "py.flask.two"}


def test_schema_version_bump_invalidates_the_cache(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    first = rs.build_registry_config("python", set(), str(cache), str(registry))
    Path(first.path).write_text(yaml.safe_dump({"rules": [_rule("sentinel.untouched")]}))

    with mock.patch.object(rs, "REGISTRY_CONFIG_SCHEMA_VERSION", rs.REGISTRY_CONFIG_SCHEMA_VERSION + 1):
        after_bump = rs.build_registry_config("python", set(), str(cache), str(registry))

    assert after_bump.cache_hit is False
    assert _loaded_ids(after_bump.path) == {"py.one"}


def test_corrupt_cache_metadata_falls_back_to_rebuilding(tmp_path):
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])

    first = rs.build_registry_config("python", set(), str(cache), str(registry))
    Path(rs._cache_meta_path(str(cache), "python")).write_text("{ not json")

    second = rs.build_registry_config("python", set(), str(cache), str(registry))

    assert second.cache_hit is False
    assert _loaded_ids(second.path) == {"py.one"}


def test_git_clone_fingerprint_tracks_head(tmp_path):
    """A vendored clone refreshed by `git pull` moves HEAD; that alone
    must invalidate, without stat'ing every file."""
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    (registry / ".git").mkdir()

    def fake_git(cmd, **kwargs):
        assert cmd[:3] == ["git", "-C", str(registry)]
        return mock.Mock(returncode=0, stdout=fake_git.head + "\n", stderr="")

    fake_git.head = "a" * 40

    with mock.patch.object(rs.subprocess, "run", side_effect=fake_git):
        first = rs.build_registry_config("python", set(), str(cache), str(registry))
        assert first.cache_hit is False
        assert rs.build_registry_config("python", set(), str(cache), str(registry)).cache_hit is True

        fake_git.head = "b" * 40
        assert rs.build_registry_config("python", set(), str(cache), str(registry)).cache_hit is False

    meta = json.loads(Path(rs._cache_meta_path(str(cache), "python")).read_text())
    assert meta["fingerprint"] == "git:" + "b" * 40


def test_polyglot_repo_scans_every_detected_language_not_just_the_first(tmp_path):
    """The bug this replaces: run_layered_scan stopped at the first
    language with a non-empty pruned config, so a Python backend beside a
    TypeScript frontend silently lost one of the two registry layers."""
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    _write_registry(registry, "typescript", "lang", "b.yaml", [_rule("ts.one")])

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 1\n")
    (repo / "src" / "app.ts").write_text("const x = 1;\n")

    recorded: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        recorded.append(cmd)
        return mock.Mock(returncode=0, stdout='{"results": []}', stderr="")

    with mock.patch.object(rs.subprocess, "run", side_effect=fake_run):
        result = rs.run_layered_scan(
            str(repo),
            custom_config_path="does-not-matter",
            registry_root=str(registry),
            cache_dir=str(tmp_path / "cache"),
        )

    assert {c.language for c in result.registry_configs} == {"python", "typescript"}

    assert len(recorded) == 1, "the custom pack and every registry layer share one invocation"
    config_args = [a for a in recorded[0] if a.startswith("--config=")]
    assert len(config_args) == 3, "the custom pack plus both languages' pruned configs"


def test_inline_suppression_is_never_honoured(tmp_path):
    """Product policy, not a tuning choice: an ignore is requested and
    approved in the Toleman dashboard, where it carries an approval trail
    and can be revoked. Honouring a `# nosemgrep` comment would be a
    second, invisible suppression channel available to anyone with commit
    access, or to a compromised dependency."""
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1  # nosemgrep\n")

    recorded: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        recorded.append(cmd)
        return mock.Mock(returncode=0, stdout='{"results": []}', stderr="")

    with mock.patch.object(rs.subprocess, "run", side_effect=fake_run):
        rs.run_layered_scan(
            str(repo),
            custom_config_path="does-not-matter",
            registry_root=str(registry),
            cache_dir=str(tmp_path / "cache"),
        )

    assert "--disable-nosem" in recorded[0]


def test_findings_are_attributed_to_the_layer_that_produced_them(tmp_path):
    """One invocation still has to report the layers separately: the
    registry's rules are broad and generic by construction, so a caller
    may gate a PR on the custom pack alone."""
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")

    results = {
        "results": [
            {"check_id": "app.scanners.rules.core.injection.toleman-sql-injection", "path": "app.py"},
            {"check_id": "python-registry-pruned.py.one", "path": "app.py"},
        ]
    }

    import json as _json

    with mock.patch.object(
        rs.subprocess, "run",
        return_value=mock.Mock(returncode=0, stdout=_json.dumps(results), stderr=""),
    ):
        result = rs.run_layered_scan(
            str(repo),
            custom_config_path="does-not-matter",
            registry_root=str(registry),
            cache_dir=str(tmp_path / "cache"),
        )

    assert [f["check_id"] for f in result.custom_findings] == [
        "app.scanners.rules.core.injection.toleman-sql-injection"
    ]
    assert [f["check_id"] for f in result.registry_findings] == ["python-registry-pruned.py.one"]
    assert len(result.findings) == 2


def test_language_with_no_matching_registry_rules_is_skipped(tmp_path):
    """An empty pruned config is not worth a --config slot; it would just
    make semgrep parse a rules-less file on every scan."""
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "a.yaml", [_rule("py.one")])
    _write_registry(registry, "typescript", "lang", "b.yaml", [_rule("ts.noise", category="correctness")])

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    (repo / "app.ts").write_text("const x = 1;\n")

    with mock.patch.object(rs.subprocess, "run", return_value=mock.Mock(returncode=0, stdout='{"results": []}', stderr="")):
        result = rs.run_layered_scan(
            str(repo),
            custom_config_path="does-not-matter",
            registry_root=str(registry),
            cache_dir=str(tmp_path / "cache"),
        )

    assert [c.language for c in result.registry_configs] == ["python"]


def test_typescript_pulls_the_javascript_registry_folder_too(tmp_path):
    """semgrep-rules keeps the bulk of its JS/TS security rules under
    javascript/, most of them declaring `languages: [javascript,
    typescript]`. Pruning a TypeScript repo against typescript/ alone
    measured 1 rule against the real clone where both folders give ~170,
    so the alias is coverage, not tidiness."""
    registry = tmp_path / "registry"
    _write_registry(registry, "typescript", "lang", "ts.yaml", [_rule("ts.only.one")])
    _write_registry(registry, "javascript", "lang", "js.yaml", [
        _rule("js.shared.two"),
        _rule("ts.only.one"),  # same id in both folders must collapse
    ])

    pruned = rs.build_registry_config("typescript", set(), str(tmp_path / "cache"), str(registry))

    assert _loaded_ids(pruned.path) == {"ts.only.one", "js.shared.two"}
    assert pruned.rule_count == 2


def test_a_language_without_an_alias_reads_only_its_own_folder(tmp_path):
    registry = tmp_path / "registry"
    _write_registry(registry, "python", "lang", "py.yaml", [_rule("py.one")])
    _write_registry(registry, "javascript", "lang", "js.yaml", [_rule("js.two")])

    pruned = rs.build_registry_config("python", set(), str(tmp_path / "cache"), str(registry))

    assert _loaded_ids(pruned.path) == {"py.one"}


def test_alias_folder_changes_invalidate_the_cache(tmp_path):
    """The fingerprint has to cover every folder the build reads, not
    just the language's own -- otherwise a refreshed javascript/ would
    leave a stale TypeScript config in place indefinitely."""
    registry = tmp_path / "registry"
    cache = tmp_path / "cache"
    _write_registry(registry, "typescript", "lang", "ts.yaml", [_rule("ts.one")])
    js_file = _write_registry(registry, "javascript", "lang", "js.yaml", [_rule("js.one")])

    first = rs.build_registry_config("typescript", set(), str(cache), str(registry))
    assert first.cache_hit is False

    js_file.write_text(yaml.safe_dump({"rules": [_rule("js.one"), _rule("js.two")]}))
    stat = js_file.stat()
    os.utime(js_file, (stat.st_atime + 10, stat.st_mtime + 10))

    second = rs.build_registry_config("typescript", set(), str(cache), str(registry))

    assert second.cache_hit is False
    assert _loaded_ids(second.path) == {"ts.one", "js.one", "js.two"}


def test_javascript_frameworks_are_detected_from_package_json(tmp_path):
    repo = tmp_path / "repo"
    (repo / "frontend").mkdir(parents=True)
    (repo / "frontend" / "package.json").write_text(
        '{"dependencies": {"react": "^19.0.0", "next": "15.1.0"},'
        ' "devDependencies": {"typescript": "^5.0.0"}}'
    )
    (repo / "frontend" / "page.tsx").write_text("export default function P() { return null }\n")

    assert rs.detect_technologies(str(repo), "typescript") == {"react"}


def test_javascript_frameworks_are_detected_from_imports_without_a_manifest(tmp_path):
    """Same reason the Python detector greps imports: a sub-app can use a
    framework no manifest in the tree declares."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.js").write_text("const express = require('express');\n")
    (repo / "client.js").write_text("import { sign } from 'jsonwebtoken';\n")

    assert rs.detect_technologies(str(repo), "javascript") == {"express", "jsonwebtoken"}


def test_subpath_imports_count_for_their_package(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "route.ts").write_text("import { NextResponse } from 'next/server';\n")

    assert rs.detect_technologies(str(repo), "typescript") == {"react"}


def test_a_package_name_prefix_is_not_a_match(tmp_path):
    """`expressive` must not select the express rule folder -- the import
    pattern anchors on the closing quote for exactly this reason."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("import x from 'expressive';\n")
    (repo / "package.json").write_text('{"dependencies": {"expressive": "^1.0.0"}}')

    assert rs.detect_technologies(str(repo), "javascript") == set()
