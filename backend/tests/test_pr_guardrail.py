from app.core.pr_guardrail import compute_net_new, highest_severity, should_block


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
