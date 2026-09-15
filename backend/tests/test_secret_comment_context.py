"""Secret findings say when the line is a comment (#481 item 2).

The finding that prompted #481 was a High `generic-api-key` on a line that
turned out to be a comment inside a Semgrep rule file, quoting a published
RailsGoat fixture as that rule's validation evidence. #499 added the
matched value's length and character class; this adds the other fact that
settled it.

It could not go in the parser: gitleaks reports no source line, its `Match`
excludes the comment prefix (on that finding it began at
`secret_key_base = "..."`, column 33), and `StartColumn` alone cannot
separate indented code from a short comment prefix. The only reliable
source is the file, and parsers are handed stdout with no repository.

The annotation is context for a human, never grounds to downgrade or
suppress. A credential someone commented out rather than deleted is still
committed, still in history, and still needs rotating -- so the note says
so, and the severity does not move.
"""
from pathlib import Path

from app.models.models import Severity
from app.scanners import secret_context


def _item(path="a.py", line=1, description="Detected a Generic API Key."):
    return {
        "rule_id": "generic-api-key",
        "title": "Secret detected: generic-api-key",
        "description": description,
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "severity": Severity.HIGH,
        "snippet": "",
        "cve_id": None,
    }


def test_comment_markers_across_the_scanned_languages():
    for line in (
        '# python',
        '## the exact shape from the finding that prompted this',
        '// java or go',
        '-- sql or lua',
        '/* c block open */',
        ' * c block continuation',
        '<!-- html -->',
        '; ini',
        '% erlang',
    ):
        assert secret_context.line_looks_like_a_comment(line), line


def test_code_lines_are_not_comments():
    for line in (
        'AWS_KEY = "x"',
        '    token = get()',
        'return 1 * 2',
        '',
        '   ',
    ):
        assert not secret_context.line_looks_like_a_comment(line), line


def test_a_trailing_comment_is_deliberately_not_reported():
    """A credential on a code line with a trailing comment sits in the code
    half as often as the comment half. Saying "comment" there would be
    wrong exactly when it matters, so this errs towards silence."""
    assert not secret_context.line_looks_like_a_comment('token = "x"  # a note')


def test_a_commented_line_is_annotated(tmp_path):
    (tmp_path / "rule.yaml").write_text('rules:\n## secret_key_base = "..."\n')
    item = _item(path="rule.yaml", line=2)

    secret_context.annotate(item, "gitleaks", tmp_path)

    assert "This line is a comment" in item["description"]
    # The original description survives; this is additive.
    assert "Detected a Generic API Key." in item["description"]
    # And nothing about the verdict moves.
    assert item["severity"] == Severity.HIGH


def test_a_code_line_is_left_alone(tmp_path):
    (tmp_path / "app.py").write_text('AWS_KEY = "real"\n')
    item = _item(path="app.py", line=1)

    secret_context.annotate(item, "gitleaks", tmp_path)

    assert item["description"] == "Detected a Generic API Key."


def test_non_secret_tools_are_untouched(tmp_path):
    """A semgrep finding on a commented-out line is a different
    conversation -- dead code, not a leaked credential."""
    (tmp_path / "app.py").write_text('# x = eval(user)\n')
    item = _item(path="app.py", line=1)

    secret_context.annotate(item, "semgrep", tmp_path)

    assert "comment" not in item["description"]


def test_an_unreadable_file_annotates_nothing(tmp_path):
    """Silence is correct for a deleted file or a path that normalised
    outside the checkout. Its absence must never read as "not a comment"
    -- which is why this is additive-only and never sets a negative flag."""
    item = _item(path="gone.py", line=4)

    secret_context.annotate(item, "gitleaks", tmp_path)

    assert item["description"] == "Detected a Generic API Key."


def test_a_line_number_past_the_end_of_the_file_is_safe(tmp_path):
    (tmp_path / "short.py").write_text("one\n")
    item = _item(path="short.py", line=99)

    secret_context.annotate(item, "gitleaks", tmp_path)

    assert item["description"] == "Detected a Generic API Key."


def test_a_missing_line_number_is_safe(tmp_path):
    (tmp_path / "a.py").write_text("# c\n")
    item = _item(path="a.py")
    item["line_start"] = None

    secret_context.annotate(item, "gitleaks", tmp_path)

    assert item["description"] == "Detected a Generic API Key."


def test_reading_stops_at_the_requested_line(tmp_path):
    """Runs once per finding, and a scan can hit a large vendored file."""
    (tmp_path / "big.py").write_text("\n".join(f"line{i}" for i in range(1, 5001)) + "\n")

    assert secret_context.read_line(tmp_path, "big.py", 3) == "line3\n"
    assert secret_context.read_line(tmp_path, "big.py", 50_000) is None


def test_noseyparker_is_also_a_secret_tool():
    assert "noseyparker" in secret_context.SECRET_TOOLS
    assert "gitleaks" in secret_context.SECRET_TOOLS
