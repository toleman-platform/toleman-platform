"""Findings a PR did not introduce must not be reported against it.

A dedup hash is a fingerprint of `rule_id|file_path|tool|snippet`, and the
net-new diff (app.core.pr_guardrail.compute_net_new) is hash equality
against the default branch's last scan. Anything that moves a hash without a
person touching the code moves a *pre-existing* finding into the net-new
set: semgrep's `--config=auto` is an unpinned registry, so an upstream rule
rename (`...logging.python-logger-credential-disclosure` becoming
`...logging.logger-credential-leak.python-logger-credential-disclosure`)
silently reclassifies an old finding as new; so does a scanner upgrade, a
tool enabled for the PR surface but not the default-branch scan, or a
baseline nobody has refreshed.

The symptom is a PR touching one workflow file being told it introduced four
vulnerabilities in backend Python modules its author never opened. The fix
is that authorship is decided by the diff, not by hash equality; these tests
pin that, and pin equally hard that the filter can never become a new way
for a real finding to vanish.
"""

import json
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core import pr_guardrail_executor as executor
from app.core.pr_guardrail import WHOLE_FILE, attributable_to_diff
from app.models.models import Organization, PRGuardrailStatus, Scan, Target, Workspace


def finding(path, line=None, line_end=None, rule="r", tool="semgrep"):
    return {
        "tool": tool,
        "rule_id": rule,
        "title": rule,
        "file_path": path,
        "line_start": line,
        "line_end": line_end,
        "severity": "Medium",
    }


class TestAttribution:
    def test_untouched_file_is_dropped(self):
        """The reported bug: a PR that changed only a workflow file was told
        it introduced findings in backend/app/core/github_token.py."""
        net_new = [
            finding(".github/workflows/publish-images.yml", 40),
            finding("backend/app/core/github_token.py", 55),
            finding("backend/app/api/github_token.py", 141),
        ]
        kept = attributable_to_diff(net_new, {".github/workflows/publish-images.yml": {40, 41}})
        assert [f["file_path"] for f in kept] == [".github/workflows/publish-images.yml"]

    def test_untouched_line_in_a_touched_file_is_dropped(self):
        """Editing line 10 of a file does not make its line 900 yours."""
        kept = attributable_to_diff([finding("a.py", 900)], {"a.py": {10, 11}})
        assert kept == []

    def test_changed_line_is_kept(self):
        kept = attributable_to_diff([finding("a.py", 11)], {"a.py": {10, 11}})
        assert len(kept) == 1

    def test_multi_line_match_counts_if_any_line_moved(self):
        """An author who changed one argument of a five-line call introduced
        what that call now does."""
        kept = attributable_to_diff([finding("a.py", 10, line_end=14)], {"a.py": {13}})
        assert len(kept) == 1

    def test_finding_with_no_line_in_a_changed_file_is_kept(self):
        """SCA/license findings carry no source line. A dependency added in
        this PR is exactly what must survive the filter."""
        kept = attributable_to_diff(
            [finding("backend/requirements.txt", None, tool="trivy")],
            {"backend/requirements.txt": {3}},
        )
        assert len(kept) == 1

    def test_finding_with_no_line_in_an_untouched_file_is_dropped(self):
        kept = attributable_to_diff(
            [finding("backend/requirements.txt", None, tool="trivy-license")],
            {"README.md": {1}},
        )
        assert kept == []

    def test_whole_file_sentinel_keeps_everything_in_that_file(self):
        """GitHub omits `patch` for binaries and oversized diffs, and a pure
        rename carries no hunks. Unknown lines must suppress nothing."""
        kept = attributable_to_diff([finding("a.py", 900)], {"a.py": WHOLE_FILE})
        assert len(kept) == 1

    def test_empty_line_set_is_not_the_whole_file_sentinel(self):
        """The two must stay distinguishable: WHOLE_FILE keeps everything, a
        genuinely empty changed-line set keeps nothing."""
        assert attributable_to_diff([finding("a.py", 900)], {"a.py": set()}) == []

    def test_path_prefixes_do_not_decide_authorship(self):
        kept = attributable_to_diff([finding("./a/b.py", 5)], {"a/b.py": {5}})
        assert len(kept) == 1

    def test_absurd_line_span_does_not_hang_the_walk(self):
        kept = attributable_to_diff([finding("a.py", 1, line_end=10**9)], {"a.py": {3}})
        assert len(kept) == 1


class TestPatchParsing:
    def test_added_lines_are_numbered_off_the_head_side(self):
        patch = "\n".join([
            "@@ -10,3 +10,4 @@ def f():",
            " context",
            "-removed",
            "+added one",
            "+added two",
            " trailing",
        ])
        # head side: 10 context, 11 added one, 12 added two, 13 trailing
        assert executor._added_lines_from_patch(patch) == {11, 12}

    def test_multiple_hunks(self):
        patch = "\n".join([
            "@@ -1,2 +1,3 @@",
            " a",
            "+b",
            " c",
            "@@ -50,1 +51,2 @@",
            " x",
            "+y",
        ])
        assert executor._added_lines_from_patch(patch) == {2, 52}

    def test_single_line_hunk_header_without_a_count(self):
        assert executor._added_lines_from_patch("@@ -1 +7 @@\n+only") == {7}

    def test_no_newline_marker_is_not_a_line(self):
        patch = "@@ -1,1 +1,2 @@\n a\n+b\n\\ No newline at end of file"
        assert executor._added_lines_from_patch(patch) == {2}

    def test_text_before_the_first_hunk_is_ignored(self):
        """Nothing outside a hunk has a head-side line number; counting it
        would number every following line from zero."""
        assert executor._added_lines_from_patch("diff --git a/x b/x\n+not a hunk line") == set()


class TestChangedLineMap:
    def test_missing_patch_maps_to_whole_file_not_to_nothing(self):
        """A binary file, an oversized diff and a rename are all genuinely
        part of the PR. Mapping them to an empty set would silently drop
        every finding in them."""
        entries = [{"filename": "logo.png", "status": "modified"}]
        assert executor._changed_line_map(entries) == {"logo.png": WHOLE_FILE}

    def test_deleted_files_are_absent_from_the_map(self):
        entries = [
            {"filename": "gone.py", "status": "removed", "patch": "@@ -1,1 +0,0 @@\n-x"},
            {"filename": "kept.py", "status": "modified", "patch": "@@ -1,1 +1,2 @@\n x\n+y"},
        ]
        assert executor._changed_line_map(entries) == {"kept.py": {2}}


class TestUnavailableDiffNeverHides:
    def test_render_names_the_gap_instead_of_claiming_authorship(self):
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1, diff_attributed=False,
        )
        assert "diff could not be read" in body
        assert "introduced by this PR" not in body

    def test_attributed_render_claims_authorship(self):
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1, diff_attributed=True,
        )
        assert "introduced by this PR" in body
        assert "diff could not be read" not in body

    def test_default_reproduces_the_old_comment(self):
        """Callers predating this filter must render exactly what they did."""
        body = executor.render_comment([], [], PRGuardrailStatus.PASSED, 1, 1)
        assert "vs the default branch. ✅" in body
        assert "diff could not be read" not in body

    def test_pr_files_api_failure_returns_none_not_empty(self, monkeypatch):
        """None means "we do not know what changed". An empty list would mean
        "nothing changed", which would attribute nothing and pass clean."""
        def boom(path, token=""):
            raise RuntimeError("GitHub is down")

        monkeypatch.setattr(executor, "github_get", boom)
        assert executor._pr_files("o/r", 1) is None


class TestRealPullRequests:
    """The same logic against verbatim `GET /pulls/{n}/files` payloads from
    toleman-platform/demo-repository (tests/fixtures/demo_repository_pr_files.json).

    Hand-written patches are a model of GitHub's output; these are the
    output. They cover the shapes that matter and that a synthetic fixture
    tends to get wrong: many small scattered hunks in one file, several
    files in one PR, and a deletion.
    """

    @pytest.fixture(scope="class")
    def prs(self):
        path = Path(__file__).parent / "fixtures" / "demo_repository_pr_files.json"
        return json.loads(path.read_text())

    def test_scattered_hunks_attribute_only_the_lines_touched(self, prs):
        """demo-repository#4 pins 10 action SHAs scattered through a
        120-line workflow. This is PR #342's shape exactly: a small edit to
        one file, with the rest of that file -- and the rest of the repo --
        someone else's work."""
        changed = executor._changed_line_map(prs["4"])
        wf = ".github/workflows/toleman-scan.yml"
        assert changed[wf] == {39, 44, 55, 66, 75, 86, 97, 99, 105, 116}

        kept = attributable_to_diff(
            [
                finding(wf, 39),   # a line this PR rewrote
                finding(wf, 40),   # its immediate neighbour, untouched
                finding(wf, 2),    # top of the file, untouched
                finding("README.md", 1),  # a file this PR never opened
            ],
            changed,
        )
        assert [f["line_start"] for f in kept] == [39]

    def test_line_sets_do_not_leak_between_files_in_one_pr(self, prs):
        """demo-repository#6 changes two workflows. Line 16 is the author's
        in one of them and nobody's in the other."""
        changed = executor._changed_line_map(prs["6"])
        assert changed[".github/workflows/auto-assign.yml"] == {7, 16, 17, 18, 19, 20, 21}
        assert changed[".github/workflows/proof-html.yml"] == {5, 6, 11}

        kept = attributable_to_diff(
            [
                finding(".github/workflows/auto-assign.yml", 16),
                finding(".github/workflows/proof-html.yml", 16),
            ],
            changed,
        )
        assert [f["file_path"] for f in kept] == [".github/workflows/auto-assign.yml"]

    def test_a_deleted_file_attributes_nothing(self, prs):
        """demo-repository#7 deletes a workflow. GitHub still sends a patch
        for it (all `-` lines); there is no file left in the checkout for a
        scanner to flag, so it must not appear in the map at all."""
        assert executor._changed_line_map(prs["7"]) == {}
        assert attributable_to_diff([finding(".github/workflows/toleman-scan.yml", 3)], {}) == []

    def test_appended_lines_at_the_top_of_a_file(self, prs):
        changed = executor._changed_line_map(prs["1"])
        assert changed["README.md"] == {1, 2, 3, 4}
        kept = attributable_to_diff([finding("README.md", 4), finding("README.md", 5)], changed)
        assert [f["line_start"] for f in kept] == [4]


class TestEndpointAttribution:
    """The reported comment also announced 15 "new" API endpoints in files
    the PR never opened. Informational, but still a claim about what this
    author did."""

    def _endpoint(self, file, line, route="/x", method="GET"):
        return {"method": method, "route": route, "file": file, "line": line}

    def test_endpoints_outside_the_diff_are_dropped(self):
        kept = executor._attributable_endpoints(
            [
                self._endpoint("backend/app/api/pr_guardrail.py", 275),
                self._endpoint("backend/app/api/new_feature.py", 12),
            ],
            {"backend/app/api/new_feature.py": {10, 11, 12}},
        )
        assert [e["file"] for e in kept] == ["backend/app/api/new_feature.py"]

    def test_unavailable_diff_leaves_the_list_untouched(self):
        endpoints = [self._endpoint("a.py", 1)]
        assert executor._attributable_endpoints(endpoints, None) == endpoints

    def test_endpoint_dicts_survive_the_round_trip_unchanged(self):
        """The filter selects; it must not reshape what render_comment reads."""
        e = self._endpoint("a.py", 5, route="/findings/{id}", method="POST")
        kept = executor._attributable_endpoints([e], {"a.py": {5}})
        assert kept == [e]
        assert "_endpoint" not in kept[0]


class TestEndToEnd:
    """The whole path, PR #342's exact shape: a PR that edits one workflow
    file, scanned by a tool that reports findings across the repository.

    Boundary mocking follows tests/test_pr_guardrail_carry_forward.py: real
    dedup, diff, policy and status logic; only the GitHub API, git clone,
    scanner subprocess and outbound HTTP are faked.
    """

    @pytest.fixture()
    def engine(self):
        eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        SQLModel.metadata.create_all(eng)
        return eng

    def _make_target(self, engine):
        with Session(engine) as session:
            org = Organization(name="org")
            session.add(org)
            session.commit()
            session.refresh(org)
            ws = Workspace(organization_id=org.id, name="ws", api_key="k")
            session.add(ws)
            session.commit()
            session.refresh(ws)
            t = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
            session.add(t)
            session.commit()
            session.refresh(t)
            # GH-07: without a completed baseline scan the diff is skipped
            # entirely and nothing is reported for any reason.
            session.add(Scan(target_id=t.id, tool="semgrep", branch=t.default_branch, status="completed"))
            session.commit()
            return t.id

    def _wire(self, monkeypatch, findings, pr_files):
        class Res:
            def __init__(self, data):
                self._data = data

            def raise_for_status(self):
                pass

            def json(self):
                return self._data

        def fake_get(path, **kwargs):
            if "/files" in path:
                # page 2 onward is empty, as GitHub's paging really behaves
                return Res(pr_files if "page=1" in path else [])
            return Res({"head": {"ref": "feature", "sha": "deadbeef"}, "title": "a pr"})

        monkeypatch.setattr(executor, "github_get", fake_get)
        monkeypatch.setattr(executor, "resolve_github_token", lambda session, workspace_id, slug: None)
        monkeypatch.setattr(executor.runner, "clone_repo", lambda *a, **k: "/tmp/fake-repo")
        monkeypatch.setattr(executor.runner, "normalize_file_path", lambda fp, repo_path: fp)
        monkeypatch.setattr(executor, "_diff_new_endpoints", lambda session, target, repo_path: [])
        monkeypatch.setattr(executor, "_get_installation_token_or_none", lambda session, target: None)
        monkeypatch.setattr(executor.runner, "run_tool", lambda tool, repo_path, paths=None: {"_tool": tool})
        monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"semgrep": lambda raw: list(findings)})
        monkeypatch.setattr(executor, "set_commit_status", lambda session, target, sha, state, description: None)
        posted = []
        monkeypatch.setattr(
            executor, "post_pr_comment", lambda session, target, pr_number, body: posted.append(body)
        )
        return posted

    # The reported PR: one workflow file, 16 added lines, nothing else.
    PR_342_FILES = [{
        "filename": ".github/workflows/publish-images.yml",
        "status": "modified",
        "patch": "@@ -40,6 +40,9 @@ jobs:\n   steps:\n+          cache-from: type=gha\n"
                 "+          cache-to: type=gha,mode=max\n+\n   more",
    }]

    def test_findings_in_untouched_files_are_not_reported_against_the_pr(self, engine, monkeypatch):
        """A scanner rule rename moved four pre-existing findings into the
        net-new set. None of them are this author's."""
        target_id = self._make_target(engine)
        posted = self._wire(
            monkeypatch,
            [
                finding("backend/app/core/github_token.py", 55, rule="logger-credential-leak"),
                finding("backend/app/core/github_token.py", 62, rule="logger-credential-leak"),
                finding("backend/app/api/github_token.py", 141, rule="logger-credential-leak"),
                finding("backend/requirements.txt", None, rule="license:BSD-3-Clause", tool="semgrep"),
            ],
            self.PR_342_FILES,
        )

        with Session(engine) as session:
            result = executor.execute_pr_guardrail_scan(session.get(Target, target_id), 342, session)

        assert result["new_findings_count"] == 0
        assert result["status"] == PRGuardrailStatus.PASSED
        assert "github_token.py" not in posted[0]
        assert "introduced by this PR" in posted[0]

    def test_a_finding_on_a_line_the_pr_added_is_still_reported(self, engine, monkeypatch):
        """The filter must not become a way to pass a PR that really did
        introduce something."""
        target_id = self._make_target(engine)
        bad = finding(".github/workflows/publish-images.yml", 41, rule="script-injection")
        bad["severity"] = "Critical"
        posted = self._wire(
            monkeypatch,
            [bad, finding("backend/app/core/github_token.py", 55)],
            self.PR_342_FILES,
        )

        with Session(engine) as session:
            result = executor.execute_pr_guardrail_scan(session.get(Target, target_id), 342, session)

        assert result["new_findings_count"] == 1
        assert result["status"] == PRGuardrailStatus.BLOCKED
        assert "script-injection" in posted[0]
        assert "github_token.py" not in posted[0]

    def test_an_unreadable_diff_reports_everything_and_says_so(self, engine, monkeypatch):
        """Never silently resolved toward hiding findings: if the diff can't
        be read, the old behaviour stands and the comment names the gap."""
        target_id = self._make_target(engine)
        posted = self._wire(
            monkeypatch, [finding("backend/app/core/github_token.py", 55)], self.PR_342_FILES
        )
        monkeypatch.setattr(executor, "_pr_files", lambda slug, pr_number, token="": None)

        with Session(engine) as session:
            result = executor.execute_pr_guardrail_scan(session.get(Target, target_id), 342, session)

        assert result["new_findings_count"] == 1
        assert "diff could not be read" in posted[0]
        assert "introduced by this PR" not in posted[0]
