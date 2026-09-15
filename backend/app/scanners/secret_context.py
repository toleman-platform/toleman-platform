"""Comment context for secret findings (#481 item 2).

Toleman's own PR Guardrail blocked #480 with a High `generic-api-key` on a
line that turned out to be a comment inside a Semgrep rule file, quoting a
published RailsGoat fixture as that rule's validation evidence. The finding
gave a severity, a rule id, a path and a line, so establishing "this is a
comment" meant opening the file. #499 added the matched value's length and
character class, which is derivable from what gitleaks reports; this adds
the other fact that settled it.

Why it lives here and not in parsers.py: gitleaks reports no source line.
Its `Match` field excludes the comment prefix -- on that finding it began
at `secret_key_base = "..."`, column 33 of the line -- and `StartColumn`
alone is too weak a proxy, since indented code and a short comment prefix
are indistinguishable by column number. The only reliable source is the
file, and parsers are handed a tool's stdout with no repository. The scan
and PR Guardrail paths both already have `repo_path` and already mutate
each parsed item to normalise its path, so that is the seam.

This is a signal for a human to weigh, NOT a reason to downgrade or
suppress anything. Secrets in comments are frequently real: a credential
someone commented out rather than deleted is still committed, still in
history, and still needs rotating. The whole point of #481 is that the
triager could not see the facts; the fix is to show them, not to start
making the judgement on their behalf.
"""
from pathlib import Path

# Tools whose findings are secrets, and therefore the only ones this
# annotation means anything for. A Semgrep finding on a commented-out line
# is a different conversation (dead code, not a leaked credential).
SECRET_TOOLS = frozenset({"gitleaks", "noseyparker"})

# Line-leading comment markers across the languages this platform scans.
# "*" is here for the continuation lines of C/Java/PHP block comments, and
# is safe at line-start: an expression beginning with a bare asterisk is
# not valid in any of them.
_COMMENT_PREFIXES = ("#", "//", "--", ";", "/*", "*", "<!--", '"""', "'''", "%")


def line_looks_like_a_comment(line: str) -> bool:
    """Whether `line` is entirely a comment, judged from the line alone.

    Deliberately only recognises a comment that *starts* the line. Two
    known gaps, both preferred to the alternative of guessing:

      * a trailing comment on a code line (`token = x  # real-looking`) is
        not reported as a comment, because the credential there sits in the
        code half as often as the comment half, and saying "comment" would
        be wrong exactly when it matters;
      * a line in the middle of a block comment that does not begin with
        `*` is not recognised, because knowing that needs the lines above
        it and a per-language notion of where the block opened.

    Both err towards saying nothing rather than saying something false. An
    absent annotation costs the triager the file-open they already had;
    a wrong one costs them the finding.
    """
    stripped = line.strip()
    if not stripped:
        return False
    return stripped.startswith(_COMMENT_PREFIXES)


def read_line(repo_path: Path, relative_file: str, line_no: int | None) -> str | None:
    """The one source line, or None if it cannot be read.

    Stops at the requested line rather than reading the file: a scan can
    hit a large vendored file, and this runs per finding.
    """
    if not relative_file or not line_no or line_no < 1:
        return None
    try:
        with open(Path(repo_path) / relative_file, errors="ignore") as fh:
            for index, line in enumerate(fh, start=1):
                if index == line_no:
                    return line
                if index > line_no:
                    break
    except OSError:
        return None
    return None


def annotate(item: dict, tool: str, repo_path: Path) -> dict:
    """Append comment context to a secret finding's description, in place.

    A no-op for non-secret tools, and for any finding whose line cannot be
    read -- a deleted file, a symlink, a path that normalised to something
    outside the checkout. Silence is the correct outcome there: the
    annotation is additive context, and its absence must never be
    mistakable for "this is not a comment".
    """
    if tool not in SECRET_TOOLS:
        return item
    line = read_line(repo_path, item.get("file_path", ""), item.get("line_start"))
    if line is None or not line_looks_like_a_comment(line):
        return item
    note = (
        "This line is a comment. A commented-out credential is still committed and still "
        "in history, so this is context to weigh rather than a reason to dismiss it."
    )
    item["description"] = " ".join(part for part in (item.get("description", ""), note) if part)
    return item
