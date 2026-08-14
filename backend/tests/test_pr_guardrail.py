from unittest.mock import Mock, patch

from app.core.pr_guardrail import compute_net_new, highest_severity, should_block
from app.core.pr_guardrail_executor import (
    COMMENT_MARKER,
    _find_existing_comment_id,
    post_pr_comment,
    render_comment,
)
from app.models.models import PRGuardrailFinding, PRGuardrailStatus, Target


def _finding(dedup_hash, severity="Medium", rule_id="rule", file_path="a.py"):
    return {
        "dedup_hash": dedup_hash,
        "severity": severity,
        "rule_id": rule_id,
        "title": rule_id,
        "file_path": file_path,
        "line_start": 1,
    }


def test_compute_net_new_excludes_hashes_already_open_on_default_branch():
    pr_findings = [_finding("hash-a"), _finding("hash-b"), _finding("hash-c")]
    existing_hashes = {"hash-a", "hash-c"}

    net_new = compute_net_new(pr_findings, existing_hashes)

    assert [f["dedup_hash"] for f in net_new] == ["hash-b"]


def test_compute_net_new_returns_all_when_no_overlap():
    pr_findings = [_finding("hash-a"), _finding("hash-b")]
    net_new = compute_net_new(pr_findings, existing_hashes=set())
    assert len(net_new) == 2


def test_compute_net_new_returns_empty_when_fully_overlapping():
    pr_findings = [_finding("hash-a"), _finding("hash-b")]
    existing_hashes = {"hash-a", "hash-b"}
    assert compute_net_new(pr_findings, existing_hashes) == []


def test_compute_net_new_handles_empty_pr_findings():
    assert compute_net_new([], {"hash-a"}) == []


def test_compute_net_new_preserves_finding_fields():
    pr_findings = [_finding("hash-a", severity="Critical", rule_id="sql-injection", file_path="app.py")]
    net_new = compute_net_new(pr_findings, existing_hashes=set())
    assert net_new[0]["severity"] == "Critical"
    assert net_new[0]["rule_id"] == "sql-injection"
    assert net_new[0]["file_path"] == "app.py"


def test_highest_severity_picks_max_rank():
    findings = [_finding("a", severity="Low"), _finding("b", severity="Critical"), _finding("c", severity="Medium")]
    assert highest_severity(findings) == "Critical"


def test_highest_severity_none_when_empty():
    assert highest_severity([]) is None


def test_should_block_true_for_critical():
    assert should_block([_finding("a", severity="Critical")]) is True


def test_should_block_true_for_high():
    assert should_block([_finding("a", severity="High")]) is True


def test_should_block_false_for_medium_low_info_only():
    findings = [_finding("a", severity="Medium"), _finding("b", severity="Low"), _finding("c", severity="Informational")]
    assert should_block(findings) is False


def test_should_block_false_when_no_net_new_findings():
    assert should_block([]) is False


# --- render_comment() redesign (#127): severity table, collapsible sections,
# GFM finding table, shields.io badge -----------------------------------------


def _pr_finding(id, severity, rule_id="rule-1", title="A finding", file_path="a.py", line_start=10):
    return PRGuardrailFinding(
        id=id, pr_scan_id=1, tool="semgrep", rule_id=rule_id, title=title,
        file_path=file_path, line_start=line_start, severity=severity,
    )


def test_render_comment_includes_marker_even_when_clean():
    body = render_comment([], [], PRGuardrailStatus.PASSED, target_id=1, pr_scan_id=1)
    assert body.startswith(COMMENT_MARKER)


def test_render_comment_severity_count_table_reflects_mix():
    findings = [
        _pr_finding(1, "Critical"),
        _pr_finding(2, "Critical"),
        _pr_finding(3, "High"),
        _pr_finding(4, "Low"),
    ]
    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=1, pr_scan_id=1)

    # Header row names every severity column, single data row with counts --
    # a "one-line" summary table appearing before any per-finding detail.
    header_idx = body.index("| Informational | Low | Medium | High | Critical |")
    data_idx = body.index("| 0 | 1 | 0 | 1 | 2 |")
    assert header_idx < data_idx
    # The summary table appears before the first <details> block.
    assert data_idx < body.index("<details")


def test_render_comment_critical_and_high_open_medium_low_collapsed():
    findings = [
        _pr_finding(1, "Critical"),
        _pr_finding(2, "High"),
        _pr_finding(3, "Medium"),
        _pr_finding(4, "Low"),
    ]
    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=1, pr_scan_id=1)

    assert "<details open>\n<summary><strong>Critical</strong>" in body
    assert "<details open>\n<summary><strong>High</strong>" in body
    assert "<details>\n<summary><strong>Medium</strong>" in body
    assert "<details>\n<summary><strong>Low</strong>" in body
    # Never collapsed-and-open at once for the same severity.
    assert "<details open>\n<summary><strong>Medium</strong>" not in body
    assert "<details open>\n<summary><strong>Low</strong>" not in body


def test_render_comment_per_finding_gfm_table_structure():
    findings = [_pr_finding(42, "High", rule_id="sql-injection", title="SQL Injection", file_path="db.py", line_start=88)]
    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "| Severity | Rule | Title | Location | Links |" in body
    assert "|---|---|---|---|---|" in body
    assert "`sql-injection`" in body
    assert "SQL Injection" in body
    assert "`db.py:88`" in body
    assert "finding-42" in body
    assert "ignore_finding=42" in body


def test_render_comment_badge_blocked_vs_passed():
    blocked_body = render_comment([_pr_finding(1, "Critical")], [], PRGuardrailStatus.BLOCKED, target_id=1, pr_scan_id=1)
    passed_body = render_comment([], [], PRGuardrailStatus.PASSED, target_id=1, pr_scan_id=1)

    assert "https://img.shields.io/badge/status-blocked-red" in blocked_body
    assert "https://img.shields.io/badge/status-passed-brightgreen" in passed_body
    assert "status-passed-brightgreen" not in blocked_body
    assert "status-blocked-red" not in passed_body


def test_render_comment_new_endpoints_in_separate_collapsible_block():
    findings = [_pr_finding(1, "High")]
    new_endpoints = [{"method": "POST", "route": "/admin/reset", "file": "app.py", "line": 12}]
    body = render_comment(findings, new_endpoints, PRGuardrailStatus.BLOCKED, target_id=1, pr_scan_id=1)

    # The endpoints table lives in its own <details> block, not interleaved
    # with a vulnerability-severity block's table.
    endpoints_block_start = body.index("new API endpoint(s)")
    endpoints_details_start = body.rindex("<details", 0, endpoints_block_start)
    endpoints_details_end = body.index("</details>", endpoints_details_start)
    endpoints_block = body[endpoints_details_start:endpoints_details_end]

    assert "/admin/reset" in endpoints_block
    assert "Severity | Rule | Title" not in endpoints_block


# --- post_pr_comment() update-in-place fix (#127) ----------------------------


def _target():
    return Target(id=1, workspace_id=1, name="repo", repo_url="https://github.com/acme/repo")


def _mock_response(status_code=200, json_data=None):
    res = Mock()
    res.status_code = status_code
    res.json.return_value = json_data if json_data is not None else {}
    res.text = ""
    return res


def test_find_existing_comment_id_returns_none_when_no_marker():
    with patch("app.core.pr_guardrail_executor.httpx.get") as mock_get:
        mock_get.return_value = _mock_response(200, [{"id": 111, "body": "some unrelated human comment"}])
        assert _find_existing_comment_id("acme/repo", 7, "tok") is None


def test_find_existing_comment_id_finds_marker_tagged_comment():
    with patch("app.core.pr_guardrail_executor.httpx.get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            [
                {"id": 111, "body": "unrelated comment"},
                {"id": 222, "body": f"{COMMENT_MARKER}\n**Rikugan PR Guardrail**"},
            ],
        )
        assert _find_existing_comment_id("acme/repo", 7, "tok") == 222


def test_post_pr_comment_patches_existing_marker_tagged_comment_not_posts_new():
    target = _target()
    with patch("app.core.pr_guardrail_executor._get_installation_token_or_none", return_value="tok"), \
         patch("app.core.pr_guardrail_executor.httpx.get") as mock_get, \
         patch("app.core.pr_guardrail_executor.httpx.patch") as mock_patch, \
         patch("app.core.pr_guardrail_executor.httpx.post") as mock_post:
        mock_get.return_value = _mock_response(200, [{"id": 999, "body": f"{COMMENT_MARKER}\nold body"}])
        mock_patch.return_value = _mock_response(200)

        post_pr_comment(None, target, 7, f"{COMMENT_MARKER}\nnew body")

        mock_patch.assert_called_once()
        assert "issues/comments/999" in mock_patch.call_args.args[0]
        mock_post.assert_not_called()


def test_post_pr_comment_posts_new_when_no_prior_comment_exists():
    target = _target()
    with patch("app.core.pr_guardrail_executor._get_installation_token_or_none", return_value="tok"), \
         patch("app.core.pr_guardrail_executor.httpx.get") as mock_get, \
         patch("app.core.pr_guardrail_executor.httpx.patch") as mock_patch, \
         patch("app.core.pr_guardrail_executor.httpx.post") as mock_post:
        mock_get.return_value = _mock_response(200, [])
        mock_post.return_value = _mock_response(201)

        post_pr_comment(None, target, 7, f"{COMMENT_MARKER}\nfirst body")

        mock_post.assert_called_once()
        assert "issues/7/comments" in mock_post.call_args.args[0]
        mock_patch.assert_not_called()


def test_post_pr_comment_noop_when_no_installation_token():
    target = _target()
    with patch("app.core.pr_guardrail_executor._get_installation_token_or_none", return_value=None), \
         patch("app.core.pr_guardrail_executor.httpx.get") as mock_get, \
         patch("app.core.pr_guardrail_executor.httpx.post") as mock_post:
        post_pr_comment(None, target, 7, "body")
        mock_get.assert_not_called()
        mock_post.assert_not_called()
