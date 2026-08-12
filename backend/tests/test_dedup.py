from app.core.dedup import compute_dedup_hash, normalize_snippet


def test_normalize_snippet_collapses_whitespace():
    assert normalize_snippet("  foo   bar\n\tbaz  ") == "foo bar baz"


def test_same_inputs_produce_same_hash():
    a = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="query = f'SELECT {x}'")
    b = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="query = f'SELECT {x}'")
    assert a == b


def test_hash_survives_whitespace_only_diff():
    a = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="query = f'SELECT {x}'")
    b = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="  query = f'SELECT {x}'  ")
    assert a == b


def test_hash_survives_line_shift_when_snippet_present():
    a = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="same code", line_start=10)
    b = compute_dedup_hash("sql-injection", "app.py", "semgrep", snippet="same code", line_start=42)
    assert a == b


def test_hash_differs_by_rule_id():
    a = compute_dedup_hash("rule-a", "app.py", "semgrep", snippet="x")
    b = compute_dedup_hash("rule-b", "app.py", "semgrep", snippet="x")
    assert a != b


def test_hash_differs_by_file_path():
    a = compute_dedup_hash("rule", "a.py", "semgrep", snippet="x")
    b = compute_dedup_hash("rule", "b.py", "semgrep", snippet="x")
    assert a != b


def test_hash_differs_by_tool():
    a = compute_dedup_hash("rule", "a.py", "semgrep", snippet="x")
    b = compute_dedup_hash("rule", "a.py", "trivy", snippet="x")
    assert a != b


def test_falls_back_to_line_number_when_no_snippet():
    a = compute_dedup_hash("rule", "a.py", "trivy", snippet="", line_start=5)
    b = compute_dedup_hash("rule", "a.py", "trivy", snippet="", line_start=6)
    assert a != b


def test_case_insensitive_rule_and_tool():
    a = compute_dedup_hash("Rule-ID", "a.py", "Semgrep", snippet="x")
    b = compute_dedup_hash("rule-id", "a.py", "semgrep", snippet="x")
    assert a == b
