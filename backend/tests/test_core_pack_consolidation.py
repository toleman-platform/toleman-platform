"""The core pack is loaded as one consolidated file, not 62 (#501).

semgrep-core shipped in #486 loading its rules from a directory of 62
separate YAML files, which is the right shape for maintaining them -- each
carries the validation trail for its own rules -- and the wrong shape for
loading them.

Measured on this repo with three changed files, the shape of a PR Guardrail
scan: 81.6s from the directory against 17.2s from one consolidated file.
Identical rules, identical findings. It also explains why diff-scoping
looked ineffective on this tool: whole-repo 94.5s against 81.6s for three
files is only 14%, because almost none of the cost was ever in the files.

This is the finding rule_selector's own docstring already recorded for the
public registry layer -- "the registry's native layout took ~2x as long to
load as one consolidated file, for zero coverage difference" -- never
applied to our own pack.

The rule_id normalisation is what makes it safe. Semgrep derives check_id
from the config's path, parse_semgrep uses check_id as rule_id verbatim,
and rule_id feeds compute_dedup_hash. Without normalising, changing how the
pack is loaded orphans every existing finding, re-reports it as net-new,
and resurrects everything anyone had ignored.
"""
import yaml

from app.scanners import parsers, rule_selector, runner


def _pack(tmp_path, files):
    root = tmp_path / "core"
    for name, rules in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump({"rules": rules}))
    return root


def _rule(rule_id):
    return {
        "id": rule_id, "message": rule_id, "severity": "ERROR",
        "languages": ["python"], "pattern": "eval(...)",
        "metadata": {"category": "security"},
    }


def test_every_rule_survives_consolidation(tmp_path):
    """The whole change is worthless if it silently drops a rule."""
    root = _pack(tmp_path, {
        "injection/a.yaml": [_rule("one"), _rule("two")],
        "crypto/b.yaml": [_rule("three")],
    })

    out = rule_selector.build_core_config(str(root), str(tmp_path / "cache"))

    assert {r["id"] for r in yaml.safe_load(open(out))["rules"]} == {"one", "two", "three"}


def test_the_real_pack_consolidates_to_its_full_rule_count():
    """Guards against consolidation quietly losing rules as the pack grows;
    semgrep --validate reports the same number from the directory."""
    out = runner.core_config_path()

    assert out.endswith(".yaml"), "fell back to the directory config"
    assert len(yaml.safe_load(open(out))["rules"]) == 96


def test_a_duplicate_rule_id_across_files_is_collapsed(tmp_path):
    root = _pack(tmp_path, {
        "a.yaml": [_rule("dup")],
        "b.yaml": [_rule("dup"), _rule("other")],
    })

    out = rule_selector.build_core_config(str(root), str(tmp_path / "cache"))

    assert len(yaml.safe_load(open(out))["rules"]) == 2


def test_editing_a_rule_invalidates_the_cache(tmp_path):
    import os

    root = _pack(tmp_path, {"a.yaml": [_rule("one")]})
    cache = tmp_path / "cache"

    first = rule_selector.build_core_config(str(root), str(cache))
    assert {r["id"] for r in yaml.safe_load(open(first))["rules"]} == {"one"}

    edited = root / "a.yaml"
    edited.write_text(yaml.safe_dump({"rules": [_rule("one"), _rule("two")]}))
    stat = edited.stat()
    os.utime(edited, (stat.st_atime + 10, stat.st_mtime + 10))

    second = rule_selector.build_core_config(str(root), str(cache))

    assert {r["id"] for r in yaml.safe_load(open(second))["rules"]} == {"one", "two"}


def test_a_malformed_rule_file_falls_back_rather_than_shipping_a_partial_pack(tmp_path):
    """A pack missing whichever rules failed to parse is a quieter, worse
    failure than being slow: handed the directory, semgrep reports the
    parse error itself."""
    root = _pack(tmp_path, {"a.yaml": [_rule("one")]})
    (root / "broken.yaml").write_text("rules: [::: not yaml")

    assert rule_selector.build_core_config(str(root), str(tmp_path / "cache")) is None


def test_an_empty_directory_builds_nothing(tmp_path):
    (tmp_path / "empty").mkdir()

    assert rule_selector.build_core_config(str(tmp_path / "empty"), str(tmp_path / "cache")) is None


def test_the_command_uses_the_consolidated_config():
    cmd = runner.TOOL_COMMANDS["semgrep-core"]("/repo")

    config = next(a for a in cmd if a.startswith("--config="))
    assert config.endswith("core-consolidated.yaml"), config
    assert "--disable-nosem" in cmd


def test_rule_id_is_the_rules_own_id_not_the_config_path():
    """The load-bearing assertion. Consolidating puts a temp path into
    check_id -- observed:
    "var.folders.p8...T.toleman-semgrep-registry.toleman-orm-object-..." --
    and rule_id feeds compute_dedup_hash. Keying on the path would
    re-report every existing finding as net-new and resurrect every
    ignore."""
    raw = {
        "results": [
            {
                "check_id": "var.folders.xyz.T.core-consolidated.toleman-java-xxe",
                "path": "A.java",
                "start": {"line": 3}, "end": {"line": 3},
                "extra": {"message": "m", "severity": "ERROR", "metadata": {}},
            }
        ]
    }

    parsed = parsers.PARSER_MAP["semgrep-core"](raw)

    assert parsed[0]["rule_id"] == "toleman-java-xxe"


def test_a_rule_id_with_no_path_prefix_is_unchanged():
    raw = {
        "results": [
            {
                "check_id": "toleman-java-xxe", "path": "A.java",
                "start": {"line": 1}, "end": {"line": 1},
                "extra": {"message": "m", "severity": "ERROR", "metadata": {}},
            }
        ]
    }

    assert parsers.PARSER_MAP["semgrep-core"](raw)[0]["rule_id"] == "toleman-java-xxe"


def test_the_other_semgrep_tools_keep_their_existing_rule_ids():
    """Only semgrep-core is re-baselined. semgrep and semgrep-llm have
    persisted findings under their current path-derived ids, and changing
    those would orphan them for no benefit -- neither loads from a
    consolidated config."""
    assert parsers.PARSER_MAP["semgrep"] is parsers.parse_semgrep
    assert parsers.PARSER_MAP["semgrep-llm"] is parsers.parse_semgrep
    assert parsers.PARSER_MAP["semgrep-core"] is parsers.parse_semgrep_core


# --- per-tool visibility ---------------------------------------------

from app.core.pr_guardrail_executor import _render_tools_run  # noqa: E402


def test_the_scanned_with_line_reports_each_tools_time():
    """Without this the line names the tools and says nothing about what
    they cost, so a reviewer staring at a slow check cannot tell which tool
    to blame. Not hypothetical: semgrep-core shipped carrying ~80s of fixed
    rule-loading cost, and finding it meant reproducing the scan by hand
    off-platform."""
    rendered = _render_tools_run(
        ["gitleaks", "semgrep-core", "trivy"],
        {"gitleaks": 4.2, "semgrep-core": 81.6, "trivy": 8.0},
    )

    assert rendered == "semgrep-core (82s), trivy (8s), gitleaks (4s)"


def test_the_slowest_tool_comes_first():
    """That is the one being looked for."""
    rendered = _render_tools_run(["a", "b"], {"a": 1.0, "b": 99.0})

    assert rendered.startswith("b (99s)")


def test_a_tool_with_no_recorded_time_keeps_its_bare_name():
    """A zero would read as "instant" rather than "not measured"."""
    rendered = _render_tools_run(["measured", "unmeasured"], {"measured": 3.0})

    assert "unmeasured" in rendered
    assert "unmeasured (0s)" not in rendered


def test_no_timings_at_all_renders_exactly_as_before():
    """Old scan records and any caller that passes nothing must be
    unaffected."""
    assert _render_tools_run(["a", "b"], None) == "a, b"
    assert _render_tools_run(["a", "b"], {}) == "a, b"
