import hashlib
import re


def normalize_snippet(snippet: str) -> str:
    """Collapse whitespace so formatting-only diffs don't break the fingerprint."""
    return re.sub(r"\s+", " ", snippet.strip())


def compute_dedup_hash(rule_id: str, file_path: str, tool: str, snippet: str = "", line_start: int | None = None) -> str:
    """
    Fingerprint = normalized rule id + file path + tool + stable context.

    Prefers a normalized code-snippet hash (survives line-shift refactors).
    Falls back to line number only when the tool gives no snippet context
    (e.g. SCA findings with no source line, like a vulnerable dependency).
    """
    stable_context = normalize_snippet(snippet) if snippet else f"line:{line_start}"
    raw = f"{rule_id.strip().lower()}|{file_path.strip().lower()}|{tool.strip().lower()}|{stable_context}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
