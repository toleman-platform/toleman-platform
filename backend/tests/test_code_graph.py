"""Code graph / blast radius for diff-scoped PR scans (#244).

The graph exists to make #243's coverage reduction safe: a change in A.py
can make pre-existing code in B.py vulnerable, and a scan that looks only at
A.py never sees it. So the properties worth pinning are the ones that decide
whether a narrowed scan is trustworthy:

    the radius is right          direct importers are found, across layouts
    the radius is bounded        hub files and huge unions escalate instead
    an unknown radius escalates  never a quiet narrow scan
    the comment says which       the reader can judge the coverage offered

The last one is the same rule as #243 and osv_malware.py (#229): a check
that did not really run must never look like a check that passed -- and a
scan of 12 files must never read as a scan of the repository.
"""
import json
from pathlib import Path

import pytest

from app.core import code_graph
from app.core.code_graph import GraphUnavailable, build_import_graph, expand_paths
from app.core.pr_guardrail_executor import render_comment
from app.models.models import PRGuardrailStatus


def _write(root: Path, rel: str, body: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


class TestImportResolution:
    def test_finds_direct_importers(self, tmp_path):
        _write(tmp_path, "app/__init__.py")
        _write(tmp_path, "app/core/__init__.py")
        _write(tmp_path, "app/core/helper.py", "def validate(x): return x\n")
        _write(tmp_path, "app/api/__init__.py")
        _write(tmp_path, "app/api/route.py", "from app.core.helper import validate\n")

        graph, count = build_import_graph(tmp_path)
        assert graph["app/core/helper.py"] == ["app/api/route.py"]
        assert count == 5

    def test_resolves_a_nested_source_root(self, tmp_path):
        """`src/sentry/api/base.py` must resolve as `sentry.api.base`, with
        `src` recognised as a source root rather than a package. Nothing
        configures this -- it comes from walking up while __init__.py exists."""
        _write(tmp_path, "src/sentry/__init__.py")
        _write(tmp_path, "src/sentry/api/__init__.py")
        _write(tmp_path, "src/sentry/api/base.py", "X = 1\n")
        _write(tmp_path, "src/sentry/tasks/__init__.py")
        _write(tmp_path, "src/sentry/tasks/run.py", "from sentry.api.base import X\n")

        graph, _ = build_import_graph(tmp_path)
        assert graph["src/sentry/api/base.py"] == ["src/sentry/tasks/run.py"]

    def test_plain_import_of_a_module(self, tmp_path):
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/target.py")
        _write(tmp_path, "pkg/user.py", "import pkg.target\n")
        graph, _ = build_import_graph(tmp_path)
        assert graph["pkg/target.py"] == ["pkg/user.py"]

    def test_from_package_import_module(self, tmp_path):
        """`from pkg import target` names a *module*, not a symbol -- the
        edge is to target.py, and missing it would lose real coverage."""
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/target.py")
        _write(tmp_path, "pkg/user.py", "from pkg import target\n")
        graph, _ = build_import_graph(tmp_path)
        assert graph["pkg/target.py"] == ["pkg/user.py"]

    def test_relative_imports(self, tmp_path):
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/sub/__init__.py")
        _write(tmp_path, "pkg/shared.py")
        _write(tmp_path, "pkg/sub/leaf.py", "from ..shared import thing\nfrom . import sibling\n")
        _write(tmp_path, "pkg/sub/sibling.py")

        graph, _ = build_import_graph(tmp_path)
        assert graph["pkg/shared.py"] == ["pkg/sub/leaf.py"]
        assert graph["pkg/sub/sibling.py"] == ["pkg/sub/leaf.py"]

    def test_relative_import_climbing_past_the_root_is_dropped(self, tmp_path):
        """Resolving it to *something* would be worse than resolving it to
        nothing: a wrong edge silently redirects a scan's radius."""
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/leaf.py", "from ....way.up import thing\n")
        graph, _ = build_import_graph(tmp_path)
        assert graph == {}

    def test_third_party_and_stdlib_are_not_edges(self, tmp_path):
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/a.py", "import os\nimport httpx\nfrom fastapi import FastAPI\n")
        graph, _ = build_import_graph(tmp_path)
        assert graph == {}

    def test_self_import_is_not_an_edge(self, tmp_path):
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/a.py", "import pkg.a\n")
        graph, _ = build_import_graph(tmp_path)
        assert "pkg/a.py" not in graph

    def test_an_unparseable_file_does_not_sink_the_graph(self, tmp_path):
        """Its own outgoing edges are unknown, but it stays a valid target of
        other files' imports -- and every other file's edges still resolve."""
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/broken.py", "def (((( not python\n")
        _write(tmp_path, "pkg/good.py", "from pkg import broken\n")
        graph, _ = build_import_graph(tmp_path)
        assert graph["pkg/broken.py"] == ["pkg/good.py"]

    def test_vendor_directories_are_not_walked(self, tmp_path):
        _write(tmp_path, "pkg/__init__.py")
        _write(tmp_path, "pkg/a.py")
        _write(tmp_path, "node_modules/x/__init__.py")
        _write(tmp_path, "node_modules/x/y.py", "from pkg import a\n")
        _write(tmp_path, "venv/lib/thing.py", "from pkg import a\n")
        graph, count = build_import_graph(tmp_path)
        assert graph == {}  # nothing first-party imports pkg/a.py
        assert count == 2   # only pkg/__init__.py and pkg/a.py were indexed

    def test_no_python_at_all_raises_rather_than_returning_empty(self, tmp_path):
        """An empty graph and "there is no graph" are different facts. Only
        the first would mean "nothing else is affected"."""
        _write(tmp_path, "README.md", "# hi")
        _write(tmp_path, "src/app.ts", "export const x = 1;")
        with pytest.raises(GraphUnavailable):
            build_import_graph(tmp_path)


class TestRadiusIsBounded:
    def _graph_with_fan_in(self, n):
        return {"hub.py": [f"importer_{i}.py" for i in range(n)]}

    def test_a_hub_file_escalates_instead_of_expanding(self):
        graph = self._graph_with_fan_in(code_graph.FAN_IN_CAP + 1)
        with pytest.raises(GraphUnavailable) as ei:
            expand_paths(graph, ["hub.py"])
        assert "fan-in cap" in str(ei.value)

    def test_just_under_the_cap_still_expands(self):
        graph = self._graph_with_fan_in(code_graph.FAN_IN_CAP)
        paths, added = expand_paths(graph, ["hub.py"])
        assert added == code_graph.FAN_IN_CAP
        assert len(paths) == code_graph.FAN_IN_CAP + 1

    def test_many_modest_files_can_still_blow_the_total_cap(self):
        """Each file's own fan-in is legal; the union is not. Without this
        the "diff-scoped" label would survive a scan of most of the repo."""
        graph = {
            f"changed_{i}.py": [f"imp_{i}_{j}.py" for j in range(40)]
            for i in range(20)
        }
        changed = [f"changed_{i}.py" for i in range(20)]
        with pytest.raises(GraphUnavailable) as ei:
            expand_paths(graph, changed)
        assert "full scan" in str(ei.value)

    def test_changed_file_nothing_imports_expands_to_itself(self):
        paths, added = expand_paths({}, ["lonely.py"])
        assert paths == ["lonely.py"]
        assert added == 0

    def test_overlapping_importers_are_counted_once(self):
        graph = {"a.py": ["shared.py"], "b.py": ["shared.py"]}
        paths, added = expand_paths(graph, ["a.py", "b.py"])
        assert paths == ["a.py", "b.py", "shared.py"]
        assert added == 1

    def test_a_changed_file_that_is_also_an_importer_is_not_double_counted(self):
        graph = {"a.py": ["b.py"]}
        paths, added = expand_paths(graph, ["a.py", "b.py"])
        assert paths == ["a.py", "b.py"]
        assert added == 0


class TestUnknownRadiusEscalates:
    """Every path that cannot establish a radius must return None -- the
    caller reads that as "scan everything". Returning a narrowed list on a
    guess is the false all-clear this whole feature exists to avoid."""

    class _Target:
        id = 1

    def test_no_python_in_the_repo_escalates(self, tmp_path):
        _write(tmp_path, "main.go", "package main")
        paths, added, note = code_graph.resolve_blast_radius(
            None, self._Target(), tmp_path, ["main.go"], commit_sha="abc",
        )
        assert paths is None
        assert added == 0
        assert note

    def test_a_hub_change_escalates_with_a_readable_reason(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            code_graph, "load_cached_graph",
            lambda *a, **k: {"hub.py": [f"i{n}.py" for n in range(code_graph.FAN_IN_CAP + 5)]},
        )
        paths, added, note = code_graph.resolve_blast_radius(
            None, self._Target(), tmp_path, ["hub.py"], commit_sha="abc",
        )
        assert paths is None
        assert "fan-in cap" in note

    def test_an_unexpected_error_escalates_rather_than_propagating(self, tmp_path, monkeypatch):
        """A crash in graph code must degrade to a full scan, never fail the
        PR scan outright and never narrow it."""
        def boom(*a, **k):
            raise RuntimeError("nope")

        monkeypatch.setattr(code_graph, "load_cached_graph", boom)
        paths, added, note = code_graph.resolve_blast_radius(
            None, self._Target(), tmp_path, ["a.py"], commit_sha="abc",
        )
        assert paths is None
        assert "RuntimeError" in note

    def test_empty_changed_list_escalates(self, tmp_path):
        paths, _, note = code_graph.resolve_blast_radius(
            None, self._Target(), tmp_path, [], commit_sha="abc",
        )
        assert paths is None
        assert note


class TestCachedGraphIsCommitExact:
    def test_a_graph_from_another_commit_is_not_reused(self, tmp_path, monkeypatch):
        """The whole staleness rule in one property: a graph built from a
        different commit describes a tree that no longer exists."""
        seen = {}

        class FakeSession:
            def exec(self, stmt):
                seen["queried"] = True
                class R:
                    def first(self_inner):
                        return None
                return R()

        graph = code_graph.load_cached_graph(FakeSession(), 1, "sha-that-has-no-row")
        assert graph is None
        assert seen["queried"]

    def test_no_commit_sha_means_no_cache_read_and_no_write(self):
        assert code_graph.load_cached_graph(None, 1, "") is None
        # store_graph must return before touching the session, or this raises
        code_graph.store_graph(None, 1, "", {"a.py": ["b.py"]}, 1)


class TestCommentTellsTheTruthAboutTheRadius:
    def test_expansion_is_disclosed_not_folded_into_one_number(self):
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            scan_scope="diff", files_scanned=12, blast_radius_files=10,
        )
        assert "2 changed in this PR" in body
        assert "10 that import them" in body
        assert "whole repository was not scanned" in body

    def test_no_expansion_keeps_the_original_wording(self):
        """0 is the honest rendering when the radius really was just the
        diff -- not a reason to imply an expansion happened."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            scan_scope="diff", files_scanned=3, blast_radius_files=0,
        )
        assert "only the 3 file(s) changed in this PR" in body
        assert "import them" not in body

    def test_an_expanded_clean_scan_still_gets_no_green_tick(self):
        """#243's rule survives expansion: a narrowed scan that found
        nothing is not an all-clear, however wide the radius was."""
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            scan_scope="diff", files_scanned=12, blast_radius_files=10,
        )
        assert "✅" not in body
        assert "covers the diff only" in body

    def test_a_full_scan_says_nothing_about_a_radius(self):
        body = render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            scan_scope="full", files_scanned=0, blast_radius_files=0,
        )
        assert "Diff-scoped" not in body
        assert "import them" not in body


class TestAgainstThisRepository:
    """The issue asked for a first slice "over this repo itself, where
    correctness is checkable by hand". These are hand-checked edges."""

    @pytest.fixture(scope="class")
    def repo_graph(self):
        root = Path(__file__).resolve().parents[2]
        graph, _ = build_import_graph(root)
        return graph

    def test_runner_is_imported_by_the_tasks_that_run_scanners(self, repo_graph):
        importers = repo_graph.get("backend/app/scanners/runner.py", [])
        assert "backend/app/tasks/scan_tasks.py" in importers
        assert "backend/app/core/pr_guardrail_executor.py" in importers

    def test_dedup_is_imported_by_ingestion_and_the_pr_executor(self, repo_graph):
        importers = repo_graph.get("backend/app/core/dedup.py", [])
        assert "backend/app/core/ingestion.py" in importers
        assert "backend/app/core/pr_guardrail_executor.py" in importers

    def test_models_is_the_hub_the_fan_in_cap_exists_for(self, repo_graph):
        """Empirically 69 of ~103 files at the time this was written. The
        exact number moves; the property that it is over the cap, and so
        escalates to a full scan rather than a repo-wide "diff" scan, is
        the one that matters."""
        importers = repo_graph.get("backend/app/models/models.py", [])
        assert len(importers) > code_graph.FAN_IN_CAP
        with pytest.raises(GraphUnavailable):
            expand_paths(repo_graph, ["backend/app/models/models.py"])
