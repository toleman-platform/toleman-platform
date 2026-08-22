"""Server-side code graph: blast radius for diff-scoped PR scans (#244).

Diff-scoped scanning (#243) is a coverage *reduction* bought for speed:
editing `A.py` can make pre-existing code in `B.py` vulnerable, and a scan
that only looks at `A.py` never sees it. This module answers the question
that makes the reduction safe -- **which other files does this change
affect?** -- by resolving Python imports into a file-level dependency graph
and expanding the changed-file list to include each changed file's direct
importers.

Stage 1 only (see the issue): a module-level import graph, depth 1, Python
only. Symbol-level radius (Stage 2) and call graph/dataflow (Stage 3) are
deliberately not built here.

Measured on real PR diffs from two repositories (2026-08-22, 24 samples):
diff-only scanning missed every finding a full scan reports in 11 of the 13
samples that had any; changed-files + direct importers matched the full-scan
result in **all 24**, for +0.6s (this repo) to +3.2s (getsentry/sentry,
781k LOC) over diff-only.

Three rules keep this from becoming a false all-clear:

* **Fan-in cap.** A hub module can be imported by most of the repository --
  `models.py` here is imported by 69 of 103 files; sentry's `api/base.py`
  by 643. Enumerating those produces an "expanded diff scan" that costs
  nearly what a full scan costs while still being *described* as diff
  scoped. Past FAN_IN_CAP importers this escalates to a real full scan
  instead, which is both more honest and barely more expensive.
* **Total-expansion cap.** Many individually-modest changed files can still
  sum past the point where a narrowed scan is worth describing as one, so
  the union is bounded too, not just each file's own fan-in.
* **No graph means no claim.** Any condition that leaves the radius
  unknown -- unparseable tree, a repo above MAX_GRAPH_FILES, zero resolvable
  Python -- escalates to a full scan rather than silently scanning a narrower
  set. Same rule as `runner.ToolNotApplicable` and `osv_malware`'s
  None-vs-`{}`: a check that did not really run must never look like a check
  that passed.

The graph is built from the checkout the scan already has, then persisted
(`CodeGraph`, keyed by commit sha) as a cache. Staleness is therefore not a
judgement call: a stored graph is reused only on an exact sha match, and
anything else is rebuilt from the tree in front of us. That is deliberately
stricter than the "rebuild every 24h / on merge to main" rule discussed on
the issue -- those triggers bound *how stale* a graph may be, while building
from the scanned checkout makes it exactly current by construction. The
persisted row is what #183's reachability work can later build on.

Scope limit worth stating plainly: this graph only knows Python. A PR that
changes `.ts`/`.go`/`.tf` gets no expansion from it, and the caller must not
describe such a scan as having had its blast radius checked.
"""
import ast
import logging
import os
from datetime import datetime
from pathlib import Path, PurePosixPath

from sqlmodel import Session, select

from app.models.models import CodeGraph, Target

logger = logging.getLogger(__name__)


class GraphUnavailable(Exception):
    """No import graph can be produced, or none that should be trusted to
    narrow a scan.

    Deliberately an exception rather than an empty graph, for the same
    reason `runner.ToolNotApplicable` is one: an empty graph and a graph
    with no importers are different facts, and only one of them means
    "nothing else is affected". Callers escalate to a full scan.
    """


# Directories that never hold first-party source. Pruned during the walk
# rather than filtered afterwards -- `rglob` would descend all of
# `node_modules`/`.git` before discarding the results, which on a large
# checkout is most of the walk time.
SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "site-packages", ".eggs", ".next", "vendor",
})

# Above this many Python files, building the graph stops being cheap enough
# to do inline on a PR scan. Measured: 4650 files (getsentry/sentry) parses
# in ~16s, so this bounds the build at roughly a minute on the slowest tree
# we would accept. Past it, escalate to a full scan rather than making the
# PR wait an unbounded amount of time for a radius.
MAX_GRAPH_FILES = 15000

# Past this many direct importers, a changed file is a hub: expanding it
# approximates a full scan without admitting to being one. Derived from real
# diffs -- of 15 sentry PR samples, exactly one exceeded 50 (fan-in 148,
# expanding a 3-file diff to 151 files) and two sat just under it (43, 46).
FAN_IN_CAP = 50

# The union is capped as well as each file's fan-in: twenty changed files
# with forty importers each are all individually under FAN_IN_CAP but still
# add up to a scan that is diff-scoped in name only.
MAX_EXPANDED_FILES = 400

# A single source file large enough to be generated/vendored rather than
# written. Parsing it costs more than its edges are worth, and its imports
# are rarely the interesting ones.
MAX_SOURCE_BYTES = 2_000_000


def _walk_python_files(repo_path: Path) -> list[PurePosixPath]:
    """Repo-relative paths of every first-party .py file in the checkout.

    `followlinks=False` (the `os.walk` default, made explicit) matters: a
    symlink pointing at an ancestor directory would otherwise make this walk
    forever, and a checkout is attacker-influenced input -- the repo being
    scanned is chosen by whoever registered the target.

    Raises GraphUnavailable past MAX_GRAPH_FILES, checked during the walk so
    an enormous tree is abandoned early rather than fully enumerated first.
    """
    found: list[PurePosixPath] = []
    for dirpath, dirnames, filenames in os.walk(repo_path, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            full = Path(dirpath) / name
            try:
                rel = PurePosixPath(full.relative_to(repo_path).as_posix())
            except ValueError:
                continue
            found.append(rel)
            if len(found) > MAX_GRAPH_FILES:
                raise GraphUnavailable(
                    f"repository has more than {MAX_GRAPH_FILES} Python files; "
                    "building an import graph inline would delay the scan"
                )
    return found


def _dotted_name(repo_path: Path, rel: PurePosixPath, has_init: dict) -> str | None:
    """Map a repo-relative .py path to its importable dotted module name.

    The source root is found by walking up from the file while each ancestor
    directory is a package (has ``__init__.py``), which is what makes this
    work for `src/sentry/api/base.py` -> `sentry.api.base` and
    `backend/app/core/dedup.py` -> `app.core.dedup` without either layout
    being configured anywhere.
    """
    parts = list(rel.parts)
    if not parts or not parts[-1].endswith(".py"):
        return None

    if parts[-1] == "__init__.py":
        dir_parts, own = parts[:-1], []
    else:
        dir_parts, own = parts[:-1], [parts[-1][:-3]]

    depth = 0
    probe = list(dir_parts)
    while probe:
        key = "/".join(probe)
        if key not in has_init:
            has_init[key] = (repo_path / Path(*probe) / "__init__.py").is_file()
        if not has_init[key]:
            break
        depth += 1
        probe = probe[:-1]

    pkg_parts = dir_parts[len(dir_parts) - depth:] if depth else []
    mod_parts = pkg_parts + own
    return ".".join(mod_parts) if mod_parts else None


def _resolve(name: str, module_map: dict[str, list[str]], self_path: str) -> list[str]:
    """Longest-prefix resolve of a dotted name to file(s) in this repo.

    `import a.b.c` may refer to module `a.b.c`, or to package `a.b` with `c`
    being a symbol inside it -- progressively shorter prefixes cover both.
    Names that resolve to nothing are stdlib or third-party, and are dropped:
    the graph only claims edges within the repository it was built from.

    One dotted name can map to several files when a repository contains more
    than one copy of a package -- a vendored duplicate, a test fixture tree,
    a checked-in worktree. **Every** candidate becomes an edge rather than
    an arbitrary winner. Picking one would silently attribute the import to
    the wrong copy and leave the right one out of the blast radius, which is
    a coverage loss that looks like a clean narrow scan. Over-approximating
    costs a few extra files in the radius; under-approximating costs the
    finding this feature exists to catch.
    """
    parts = name.split(".")
    for i in range(len(parts), 0, -1):
        hits = module_map.get(".".join(parts[:i]))
        if hits:
            found = [h for h in hits if h != self_path]
            if found:
                return found
    return []


def _import_targets(node, pkg_parts: list[str]) -> list[str]:
    """Dotted names one import statement could refer to.

    `from . import x` / `from ..pkg import y` are resolved against the
    importing module's own package, which is why `pkg_parts` is passed in.
    A relative import that climbs past the top of the package tree yields
    nothing rather than silently resolving to the wrong module.
    """
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]

    if not isinstance(node, ast.ImportFrom):
        return []

    if node.level:
        trim = node.level - 1
        if trim > len(pkg_parts):
            return []
        base_parts = pkg_parts[: len(pkg_parts) - trim]
        if node.module:
            base_parts = base_parts + node.module.split(".")
    elif node.module:
        base_parts = node.module.split(".")
    else:
        return []

    base_dotted = ".".join(base_parts)
    if not base_dotted:
        return []
    # Both the module itself and each imported name: `from app.core import
    # dedup` names a *module* via an alias, while `from app.core.dedup
    # import compute` names a symbol inside one.
    return [base_dotted] + [f"{base_dotted}.{a.name}" for a in node.names]


def build_import_graph(repo_path: Path) -> tuple[dict[str, list[str]], int]:
    """Build `({file_path: [files that import it]}, indexed_file_count)`.

    Keys and values are repo-relative POSIX paths, matching the shape of
    GitHub's changed-file list so the two compare without further
    normalisation.

    Stores the *importer* direction because that is the direction blast
    radius queries; the forward "what does this import" edge is its exact
    inverse and can be recovered by transposing.

    Raises GraphUnavailable when no graph can honestly be produced.
    """
    py_files = _walk_python_files(repo_path)
    if not py_files:
        raise GraphUnavailable("no Python files found to build an import graph from")

    has_init: dict[str, bool] = {}
    module_map: dict[str, list[str]] = {}
    dotted_of: dict[str, str] = {}
    for rel in py_files:
        dotted = _dotted_name(repo_path, rel, has_init)
        if not dotted:
            continue
        path = str(rel)
        dotted_of[path] = dotted
        # Every file claiming a dotted name is kept, not just the first --
        # see _resolve for why an arbitrary winner would silently narrow
        # the blast radius.
        module_map.setdefault(dotted, []).append(path)

    if not module_map:
        raise GraphUnavailable("no importable Python modules resolved in this checkout")

    imported_by: dict[str, set[str]] = {}
    for path, dotted in dotted_of.items():
        full = repo_path / path
        try:
            if full.stat().st_size > MAX_SOURCE_BYTES:
                continue
            tree = ast.parse(full.read_text(errors="replace"))
        except (SyntaxError, ValueError, OSError, RecursionError):
            # One unreadable or unparseable file is not a reason to abandon
            # the graph -- it only means this file's *outgoing* edges are
            # unknown. It stays a valid target of other files' imports.
            # RecursionError is real here: ast.walk on a pathologically
            # nested literal can blow the stack.
            continue

        is_init = path.endswith("__init__.py")
        dotted_parts = dotted.split(".")
        pkg_parts = dotted_parts if is_init else dotted_parts[:-1]

        try:
            nodes = list(ast.walk(tree))
        except RecursionError:
            continue

        for node in nodes:
            for name in _import_targets(node, pkg_parts):
                for hit in _resolve(name, module_map, path):
                    imported_by.setdefault(hit, set()).add(path)

    graph = {target: sorted(importers) for target, importers in imported_by.items()}
    return graph, len(dotted_of)


def expand_paths(
    graph: dict[str, list[str]],
    changed: list[str],
    fan_in_cap: int = FAN_IN_CAP,
    total_cap: int = MAX_EXPANDED_FILES,
) -> tuple[list[str], int]:
    """Changed files plus every file that directly imports one of them.

    Returns `(expanded_paths, added_count)`.

    Raises GraphUnavailable when a changed file's fan-in exceeds
    `fan_in_cap`, or when the union exceeds `total_cap`. Neither is a
    failure; both are the graph reporting that a narrowed scan is the wrong
    tool for this particular change, and the caller running a full scan.
    """
    base = set(changed)
    expanded = set(base)
    for path in changed:
        importers = graph.get(path)
        if not importers:
            continue
        if len(importers) > fan_in_cap:
            raise GraphUnavailable(
                f"{path} is imported by {len(importers)} files (over the {fan_in_cap} "
                "fan-in cap); scanning the full repository is both more honest and "
                "barely more expensive than expanding this far"
            )
        expanded.update(importers)

    if len(expanded) > total_cap:
        raise GraphUnavailable(
            f"the blast radius of this change reaches {len(expanded)} files (over the "
            f"{total_cap} cap); a scan this wide should be run, and described, as a full scan"
        )

    return sorted(expanded), len(expanded) - len(base)


def load_cached_graph(session: Session, target_id: int, commit_sha: str) -> dict[str, list[str]] | None:
    """A persisted graph for exactly this commit, or None.

    The sha match is exact on purpose. A graph built from a different commit
    describes a different import structure, and using it would narrow a scan
    against a tree that no longer exists -- the failure the issue's staleness
    discussion is about.
    """
    if not commit_sha:
        return None
    try:
        row = session.exec(
            select(CodeGraph).where(
                CodeGraph.target_id == target_id,
                CodeGraph.commit_sha == commit_sha,
            )
        ).first()
    except Exception:
        logger.exception("could not read cached code graph for target %s", target_id)
        return None
    if not row or not isinstance(row.edges, dict):
        return None
    return row.edges


def store_graph(
    session: Session, target_id: int, commit_sha: str, graph: dict[str, list[str]], file_count: int
) -> None:
    """Persist (or replace) this target's graph, one row per target.

    Best-effort by contract: the caller already holds a usable graph, so a
    storage failure costs a future cache hit, never this scan.

    Callers must not hold uncommitted work when calling this -- it commits,
    which would flush anything else pending on the session. At its call site
    in the PR executor the scan row is already committed and no findings
    have been staged yet.
    """
    if not commit_sha:
        return
    try:
        existing = session.exec(select(CodeGraph).where(CodeGraph.target_id == target_id)).first()
        if existing:
            existing.commit_sha = commit_sha
            existing.edges = graph
            existing.file_count = file_count
            existing.built_at = datetime.utcnow()
            session.add(existing)
        else:
            session.add(CodeGraph(
                target_id=target_id,
                commit_sha=commit_sha,
                edges=graph,
                file_count=file_count,
            ))
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("could not persist code graph for target %s", target_id)


def resolve_blast_radius(
    session: Session,
    target: Target,
    repo_path: Path,
    changed: list[str],
    commit_sha: str = "",
) -> tuple[list[str] | None, int, str]:
    """Expand `changed` to the files a scan must also examine.

    Returns `(paths, added_count, note)`:

    * `paths` is the expanded list to scan diff-scoped, or **None** meaning
      *escalate to a full scan* -- no graph, or a change whose radius the
      caps refuse to approximate.
    * `note` always explains what happened, written to be readable in a PR
      comment: the reader of a narrowed scan is entitled to know how narrow
      it was and why.

    Never raises for graph reasons. Every failure path resolves to "scan
    everything", because the alternative -- scanning less and saying nothing
    -- is the false all-clear this feature exists to avoid.
    """
    if not changed:
        return None, 0, "no changed files to expand from"

    try:
        graph = load_cached_graph(session, target.id, commit_sha)
        cached = graph is not None
        if graph is None:
            graph, file_count = build_import_graph(repo_path)
            store_graph(session, target.id, commit_sha, graph, file_count)
        paths, added = expand_paths(graph, changed)
    except GraphUnavailable as exc:
        logger.info("code graph unavailable for target %s: %s", target.id, exc)
        return None, 0, str(exc)
    except Exception as exc:
        logger.exception("code graph failed for target %s", target.id)
        return None, 0, f"code graph could not be built ({type(exc).__name__})"

    if added:
        note = (
            f"expanded to {len(paths)} file(s): the {len(changed)} changed, plus {added} "
            "that import them"
        )
    else:
        note = "no other Python file in this repository imports the changed files"
    if cached:
        note += " (cached graph)"
    return paths, added, note
