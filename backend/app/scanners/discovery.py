"""Real static-analysis route discovery: regex over source files, no fabricated data.

Covers common framework routing conventions. Not exhaustive (no AST parsing),
but every result is a genuine grep match with file:line provenance.
"""
import re
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("flask", re.compile(r'@(?:app|bp|blueprint)\.route\(\s*["\']([^"\']+)["\'](?:.*methods\s*=\s*\[([^\]]*)\])?', re.I)),
    ("fastapi", re.compile(r'@(?:app|router)\.(get|post|put|delete|patch|head|options)\(\s*["\']([^"\']+)["\']', re.I)),
    ("express", re.compile(r'(?:app|router)\.(get|post|put|delete|patch|use)\(\s*["\']([^"\']+)["\']')),
    ("gin", re.compile(r'(?:router|r|engine)\.(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"')),
    ("django", re.compile(r'path\(\s*["\']([^"\']*)["\']')),
    ("spring", re.compile(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')),
]

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".rb"}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"}


def discover_endpoints(repo_path: Path) -> list[dict]:
    results = []
    repo_root = repo_path.resolve()
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in SOURCE_EXTENSIONS:
            continue
        # A cloned repo is attacker-controlled content: git allows committing
        # a symlink, and rglob() happily follows a file-type one straight to
        # wherever it points -- read_text() would then return that target's
        # real content (anywhere on the scanning host, or another tenant's
        # concurrently-cloned checkout under the same shared scan_workdir)
        # rather than anything actually in this repo. Skip it outright
        # rather than trying to resolve+contain it: a legitimate route file
        # is never a symlink, so there is no real case to preserve here.
        if path.is_symlink():
            continue
        try:
            resolved = path.resolve()
            resolved.relative_to(repo_root)
        except (OSError, ValueError):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue

        rel_path = str(path.relative_to(repo_path))
        for line_no, line in enumerate(text.splitlines(), start=1):
            # A line matches at most one framework's route pattern, several
            # patterns overlap syntactically (e.g. `router.get("...")` reads
            # as both FastAPI and Express), so stop at the first hit instead
            # of tagging the same line under multiple frameworks.
            for framework, pattern in PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                groups = m.groups()
                if framework in ("fastapi", "gin"):
                    method, route = groups[0].upper(), groups[1]
                elif framework == "flask":
                    route, methods = groups[0], groups[1]
                    method = methods.replace("'", "").replace('"', "").strip() if methods else "GET"
                elif framework == "express":
                    method, route = groups[0].upper(), groups[1]
                else:
                    method, route = "-", groups[0]

                results.append({
                    "framework": framework,
                    "method": method,
                    "route": route,
                    "file": rel_path,
                    "line": line_no,
                })
                break
    return results
