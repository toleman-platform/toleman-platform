"""Technology-aware Semgrep rule selection (issue TBD).

Design doc: backend/app/scanners/rules/core/README.md's "Registry
integration" section. This module is the implementation of that design,
built and locally benchmarked 2026-09-12/13 -- see KT.md at the repo root
for the full validation trail (what was measured, what changed as a
result, what's still open).

Three things this module does, none of them novel individually, but not
done together anywhere else in this codebase yet:

1. Detects which frameworks a target repo actually uses -- not just from
   its root manifest (requirements.txt/pyproject.toml), but by grepping
   real import statements repo-wide. This matters: a manifest-only check
   missed a Flask sub-app embedded in an otherwise-Django repo during
   benchmarking (PyGoat's dockerized_labs/*), which cost real coverage
   until fixed. See detect_technologies().

2. Prunes the vendored github.com/semgrep/semgrep-rules registry down to
   {this repo's actual languages} x {this repo's actual frameworks} x
   {category: security} rules, consolidated into one YAML file per
   language. Un-pruned ("auto" or a whole per-language folder), that
   registry is ~28% non-security noise (compatibility/style/correctness
   rules) even before framework relevance is considered, and loading it
   as hundreds of small per-topic files (rather than one consolidated
   file) roughly doubles wall-clock scan time for no coverage gain --
   both measured, see KT.md. See build_registry_config().

3. Runs the registry layer and this repo's own custom rule pack as two
   separate Semgrep invocations with different --disable-nosem policies,
   then merges results with a nosemgrep-aware post-filter. This is
   necessary, not cosmetic: consolidating registry rules into a new file
   changes their effective check_id prefix, which silently breaks
   existing `# nosemgrep: <old-fully-qualified-id>` comments already in
   this codebase. Respecting nosemgrep on the registry layer (but not on
   our own rules -- see the custom pack's own stated security posture)
   cut a measured 15-false-positive run down to 1 on this repo's own
   source. See run_layered_scan().

Not yet wired into runner.py's TOOL_COMMANDS / tool_registry.py -- see
KT.md's "Next steps" for why that's a deliberate separate decision
(naming, default-on/off, whether the registry layer should be able to
block a PR at all) rather than a TODO left by accident.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Vendored/cached clone of https://github.com/semgrep/semgrep-rules.
# Rebuilding the pruned index below is an offline step (walks ~2000 YAML
# files) -- point this at wherever that clone is refreshed on a schedule,
# not at a URL fetched per-scan.
DEFAULT_REGISTRY_ROOT = os.environ.get("SEMGREP_RULES_REGISTRY_ROOT", "/opt/semgrep-rules")

# Bump whenever build_registry_config's pruning/merging logic changes in a
# way that would produce a different output file from the same registry
# clone -- e.g. a new category filter, a different dedupe key, a change to
# which folders are walked. Cached configs built by an older version are
# discarded rather than silently reused, which is the whole reason this is
# a constant and not just a comment.
REGISTRY_CONFIG_SCHEMA_VERSION = 2

# A detected language does not always map to exactly one registry folder.
# semgrep-rules keeps 169 security rules under javascript/ and only a
# handful under typescript/, and 153 of those javascript rules explicitly
# declare `languages: [javascript, typescript]` -- so pruning a
# TypeScript repo against typescript/ alone yielded 1 rule where the two
# folders together yield ~170. Measured on the clone, not assumed.
# Keyed by detected language; the first entry is the language's own
# folder. Add an entry here rather than special-casing a caller.
REGISTRY_LANGUAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "typescript": ("typescript", "javascript"),
}

# language -> file extensions used for the census in detect_languages().
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "java": {".java"},
    "php": {".php"},
    "ruby": {".rb"},
}

# language -> (manifest filename, package-name regex) for the fast path,
# plus an import-statement regex for the repo-wide fallback that catches
# a sub-app using a framework the root manifest never mentions.
# Extend this table, don't hand-write a new detector, when adding a
# technology folder from the registry (see build_registry_config).
TECHNOLOGY_SIGNATURES: dict[str, dict[str, "TechnologySignature"]] = {}


@dataclass
class TechnologySignature:
    technology: str  # must match a semgrep-rules/<language>/<technology> folder name
    manifest_names: tuple[str, ...]
    manifest_pattern: re.Pattern
    import_pattern: re.Pattern


def _sig(technology: str, manifest_names: tuple[str, ...], package_names: tuple[str, ...], import_names: tuple[str, ...]) -> TechnologySignature:
    return TechnologySignature(
        technology=technology,
        manifest_names=manifest_names,
        manifest_pattern=re.compile(r"(?im)^(" + "|".join(re.escape(p) for p in package_names) + r")\b"),
        import_pattern=re.compile(r"(?m)^\s*(from\s+(" + "|".join(re.escape(n) for n in import_names) + r")\b|import\s+(" + "|".join(re.escape(n) for n in import_names) + r")\b)"),
    )


def _js_sig(technology: str, package_names: tuple[str, ...]) -> TechnologySignature:
    """JavaScript/TypeScript equivalent of _sig.

    Needs its own builder because _sig's patterns are Python syntax:
    dependencies live as JSON keys in package.json rather than as
    line-leading names in requirements.txt, and imports are
    `import x from 'pkg'` / `require('pkg')` / `import 'pkg'` rather than
    `import pkg`. Subpath imports ('next/server', '@aws-sdk/client-s3')
    count as a hit for the package, which is why the import pattern
    allows a trailing path segment.
    """
    alternation = "|".join(re.escape(n) for n in package_names)
    return TechnologySignature(
        technology=technology,
        manifest_names=("package.json",),
        # A dependency entry: "express": "^4.18.0"
        manifest_pattern=re.compile(r'(?m)"(' + alternation + r')"\s*:'),
        # from 'pkg' | from "pkg/sub" | require('pkg') | import 'pkg'
        import_pattern=re.compile(
            r'''(?m)(from|require\s*\(|import)\s*\(?\s*['"](''' + alternation + r""")(/[^'"]*)?['"]"""
        ),
    )


TECHNOLOGY_SIGNATURES["python"] = {
    "django": _sig("django", ("requirements.txt", "pyproject.toml", "Pipfile"), ("django",), ("django",)),
    "flask": _sig("flask", ("requirements.txt", "pyproject.toml", "Pipfile"), ("flask",), ("flask",)),
    "fastapi": _sig("fastapi", ("requirements.txt", "pyproject.toml", "Pipfile"), ("fastapi",), ("fastapi",)),
    "pyramid": _sig("pyramid", ("requirements.txt", "pyproject.toml", "Pipfile"), ("pyramid",), ("pyramid",)),
    "sqlalchemy": _sig("sqlalchemy", ("requirements.txt", "pyproject.toml", "Pipfile"), ("sqlalchemy", "sqlmodel"), ("sqlalchemy", "sqlmodel")),
    "requests": _sig("requests", ("requirements.txt", "pyproject.toml", "Pipfile"), ("requests",), ("requests",)),
    "jwt": _sig("jwt", ("requirements.txt", "pyproject.toml", "Pipfile"), ("pyjwt", "python-jose"), ("jwt", "jose")),
    "cryptography": _sig("cryptography", ("requirements.txt", "pyproject.toml", "Pipfile"), ("cryptography",), ("cryptography",)),
    "pycryptodome": _sig("pycryptodome", ("requirements.txt", "pyproject.toml", "Pipfile"), ("pycryptodome", "pycrypto"), ("Crypto",)),
    "jinja2": _sig("jinja2", ("requirements.txt", "pyproject.toml", "Pipfile"), ("jinja2",), ("jinja2",)),
    "boto3": _sig("boto3", ("requirements.txt", "pyproject.toml", "Pipfile"), ("boto3",), ("boto3",)),
    "pymongo": _sig("pymongo", ("requirements.txt", "pyproject.toml", "Pipfile"), ("pymongo",), ("pymongo",)),
}

# JavaScript/TypeScript. Covers the registry folders that (a) hold three
# or more security rules and (b) correspond to a real npm package, so a
# package.json/import check can actually decide them. Rule counts below
# are from a 2026-09-14 semgrep-rules clone, security-category only, and
# are what justifies each entry's inclusion -- re-measure rather than
# guess when adding to this table.
#
# Deliberately NOT here: javascript/browser (10 rules). It is not a
# package, so there is no dependency or import to key on, and the
# alternative -- always-on for every JS/TS repo -- would push DOM rules
# at pure Node services without anyone having measured the false-positive
# cost. Decide it with a fixture, not by defaulting it in.
_JS_SIGNATURES = {
    "express": _js_sig("express", ("express",)),                    # 51 rules
    "angular": _js_sig("angular", ("@angular/core", "@angular/common")),  # 12
    "aws-lambda": _js_sig("aws-lambda", ("aws-sdk", "@aws-sdk/client-lambda", "aws-lambda")),  # 11
    "react": _js_sig("react", ("react", "react-dom", "next")),      # 8
    "playwright": _js_sig("playwright", ("playwright", "@playwright/test")),  # 6
    "sequelize": _js_sig("sequelize", ("sequelize",)),              # 5
    "puppeteer": _js_sig("puppeteer", ("puppeteer", "puppeteer-core")),  # 5
    "jsonwebtoken": _js_sig("jsonwebtoken", ("jsonwebtoken",)),     # 4
    "nestjs": _js_sig("nestjs", ("@nestjs/core", "@nestjs/common")),  # 3
    "node-crypto": _js_sig("node-crypto", ("crypto", "node:crypto")),  # 3
    "jquery": _js_sig("jquery", ("jquery",)),                       # 3
    "jose": _js_sig("jose", ("jose",)),                             # 3
}
# Both share one table: the registry splits its JS/TS rules across
# javascript/ and typescript/ (see REGISTRY_LANGUAGE_ALIASES) but a
# repo's dependencies are declared in the same package.json either way.
TECHNOLOGY_SIGNATURES["javascript"] = _JS_SIGNATURES
TECHNOLOGY_SIGNATURES["typescript"] = _JS_SIGNATURES

# Still empty, and honestly so: go, java, php and ruby fall back to their
# "lang" folder alone until someone measures their registry folders the
# way the tables above were measured. See HANDOFF.md.

# Every language always gets its own "lang" folder (framework-agnostic
# core security rules) regardless of detected frameworks -- not a
# TechnologySignature entry, handled directly in build_registry_config.


def detect_languages(repo_path: str, min_files: int = 1) -> list[str]:
    """Census file extensions under repo_path, skipping vendored/build
    directories. Returns languages with at least min_files matching files.
    Cheap, local, no GitHub API call -- unlike
    pipeline_workflow.detect_languages, which this deliberately doesn't
    replace; that one exists for repos Toleman doesn't have a local
    checkout of yet. This one is for a scan that already has the files on
    disk."""
    skip_dirs = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__", ".next"}
    counts: dict[str, int] = {lang: 0 for lang in LANGUAGE_EXTENSIONS}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            ext = os.path.splitext(f)[1]
            for lang, exts in LANGUAGE_EXTENSIONS.items():
                if ext in exts:
                    counts[lang] += 1
    return [lang for lang, n in counts.items() if n >= min_files]


def detect_technologies(repo_path: str, language: str) -> set[str]:
    """Manifest check first (cheap), then a repo-wide import grep as a
    fallback/supplement -- not an either/or. The import grep is what
    catches a framework used only by a sub-directory's own sub-app that
    the root manifest never declares (the PyGoat Flask-lab case this was
    built to fix). Both signals are unioned, not one overriding the
    other, since a repo can legitimately use a framework declared in a
    non-root manifest (a monorepo package) that this function's manifest
    check also won't find on its own."""
    sigs = TECHNOLOGY_SIGNATURES.get(language, {})
    found: set[str] = set()
    if not sigs:
        return found

    skip_dirs = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__", ".next"}
    manifest_names = {name for sig in sigs.values() for name in sig.manifest_names}
    manifest_text = ""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f in manifest_names:
                try:
                    manifest_text += Path(root, f).read_text(errors="ignore") + "\n"
                except OSError:
                    pass

    for tech, sig in sigs.items():
        if sig.manifest_pattern.search(manifest_text):
            found.add(tech)

    # Repo-wide import grep -- the fallback that catches an embedded
    # sub-app. Bounded to the language's own extensions so this doesn't
    # walk unrelated file types.
    exts = LANGUAGE_EXTENSIONS.get(language, set())
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if os.path.splitext(f)[1] not in exts:
                continue
            try:
                text = Path(root, f).read_text(errors="ignore")
            except OSError:
                continue
            for tech, sig in sigs.items():
                if tech in found:
                    continue
                if sig.import_pattern.search(text):
                    found.add(tech)
    return found


@dataclass
class PrunedRegistryConfig:
    """One consolidated, category=security-filtered YAML file per
    language, built once and reused across scans until the source
    registry clone or the detected technology set changes."""

    language: str
    technologies: tuple[str, ...]
    path: str
    rule_count: int
    cache_hit: bool = False  # True when this was reused, not rebuilt


def _registry_language_roots(registry_root: str, language: str) -> list[str]:
    """Existing registry folders that contribute rules for `language`,
    in priority order (the language's own folder first).

    Returns [] when the vendored clone has nothing for this language --
    callers treat that as "custom pack only", not as an error.
    """
    names = REGISTRY_LANGUAGE_ALIASES.get(language, (language,))
    return [
        os.path.join(registry_root, name)
        for name in names
        if os.path.isdir(os.path.join(registry_root, name))
    ]


def _registry_fingerprint(registry_root: str, lang_roots: list[str], folders: set[str]) -> str:
    """Cheap, content-sensitive identity for the slice of the registry
    clone that build_registry_config would actually read.

    Preferred form is the clone's git HEAD -- one subprocess, and the
    vendored clone is refreshed by pulling, so HEAD moving is exactly the
    signal we want. The stat fallback exists because the clone may be
    shipped as a plain directory (an image layer, a tarball) with no .git
    at all; it walks the same folders the build would walk but only
    stats them, which is the point -- stat'ing ~2000 files is cheap, and
    parsing them as YAML is the expensive thing this cache exists to
    avoid.

    Note the fallback deliberately hashes (path, size, mtime) rather than
    file contents: reading every file to hash it would cost roughly what
    rebuilding costs, which would make the cache pointless.
    """
    if os.path.isdir(os.path.join(registry_root, ".git")):
        try:
            proc = subprocess.run(
                ["git", "-C", registry_root, "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            head = proc.stdout.strip()
            if proc.returncode == 0 and head:
                return f"git:{head}"
        except (OSError, subprocess.SubprocessError):
            pass

    digest = hashlib.sha256()
    for lang_root in lang_roots:
        for folder in sorted(folders):
            folder_path = os.path.join(lang_root, folder)
            if not os.path.isdir(folder_path):
                continue
            for f in sorted(glob.glob(os.path.join(folder_path, "**", "*.yaml"), recursive=True)):
                try:
                    st = os.stat(f)
                except OSError:
                    continue
                digest.update(f"{f}:{st.st_size}:{int(st.st_mtime)}\n".encode())
    return f"stat:{digest.hexdigest()}"


def _cache_meta_path(out_dir: str, language: str) -> str:
    return os.path.join(out_dir, f"{language}-registry-pruned.meta.json")


def build_registry_config(
    language: str,
    technologies: set[str],
    out_dir: str,
    registry_root: str = DEFAULT_REGISTRY_ROOT,
    force_rebuild: bool = False,
) -> PrunedRegistryConfig | None:
    """Offline/build-time step: walk registry_root/<language>/{lang, each
    detected technology}, keep only metadata.category == "security"
    rules, dedupe by rule id, write ONE merged YAML file.

    The single-file requirement is not a style choice -- benchmarked both
    ways on the same rule set: preserving the registry's original
    hundreds-of-small-files layout took roughly 2x as long to load as one
    consolidated file with the identical rules, for zero coverage
    difference. See KT.md for the exact numbers.

    Result is cached in out_dir and reused when the registry fingerprint,
    the detected technology set, and REGISTRY_CONFIG_SCHEMA_VERSION all
    still match what the sidecar .meta.json records. Without this, every
    scan re-parses ~2000 registry YAML files, which costs more than the
    consolidated-file load time the pruning was introduced to save --
    i.e. the uncached version measures well in a one-shot benchmark and
    is wrong in production, so do not remove the cache to "simplify".
    Pass force_rebuild=True to bypass the check (used by the refresh job
    and by tests that need a known-cold build).

    Returns None if registry_root/<language> doesn't exist (e.g. this
    Semgrep-supported language has no registry folder, or the vendored
    clone hasn't been fetched) -- callers should fall back to the custom
    pack alone in that case, not fail the scan.
    """
    lang_roots = _registry_language_roots(registry_root, language)
    if not lang_roots:
        return None

    folders = {"lang"} | technologies
    out_path = os.path.join(out_dir, f"{language}-registry-pruned.yaml")
    meta_path = _cache_meta_path(out_dir, language)
    fingerprint = _registry_fingerprint(registry_root, lang_roots, folders)

    if not force_rebuild and os.path.isfile(out_path) and os.path.isfile(meta_path):
        try:
            meta = json.loads(open(meta_path).read())
        except (OSError, ValueError):
            meta = None
        if (
            meta
            and meta.get("schema_version") == REGISTRY_CONFIG_SCHEMA_VERSION
            and meta.get("fingerprint") == fingerprint
            and meta.get("technologies") == sorted(folders)
        ):
            return PrunedRegistryConfig(
                language=language,
                technologies=tuple(sorted(folders)),
                path=out_path,
                rule_count=meta.get("rule_count", 0),
                cache_hit=True,
            )

    all_rules: list[dict] = []
    seen_ids: set[str] = set()
    for lang_root in lang_roots:
        for folder in folders:
            folder_path = os.path.join(lang_root, folder)
            if not os.path.isdir(folder_path):
                continue
            for f in glob.glob(os.path.join(folder_path, "**", "*.yaml"), recursive=True):
                if os.sep + "tests" + os.sep in f or f.endswith(".test.yaml"):
                    continue
                try:
                    doc = yaml.safe_load(open(f))
                except Exception:
                    continue
                if not doc or "rules" not in doc:
                    continue
                for rule in doc["rules"]:
                    metadata = rule.get("metadata") or {}
                    if metadata.get("category") != "security":
                        continue
                    rule_id = rule.get("id")
                    if not rule_id or rule_id in seen_ids:
                        continue
                    seen_ids.add(rule_id)
                    all_rules.append(rule)

    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w") as fh:
        yaml.safe_dump({"rules": all_rules}, fh)
    with open(meta_path, "w") as fh:
        json.dump(
            {
                "schema_version": REGISTRY_CONFIG_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "technologies": sorted(folders),
                "language_roots": [os.path.basename(r) for r in lang_roots],
                "rule_count": len(all_rules),
            },
            fh,
        )

    return PrunedRegistryConfig(
        language=language,
        technologies=tuple(sorted(folders)),
        path=out_path,
        rule_count=len(all_rules),
        cache_hit=False,
    )


def _resolve_reported_path(repo_path: str, reported_path: str) -> str | None:
    """Turn a path out of Semgrep's JSON into one that can actually be
    opened, or None if no candidate exists.

    Semgrep reports paths relative to the *invocation* directory, echoing
    back the target argument it was given -- so scanning `..` yields
    `../backend/app/foo.py`, not `backend/app/foo.py`. Joining that onto
    repo_path produces `../../backend/app/foo.py`, which does not exist,
    and the caller's open() fails silently.

    This mattered: with a relative repo_path every nosemgrep suppression
    failed open, resurfacing 14 findings a human had already triaged and
    marked -- the precise noise the registry layer's nosemgrep-respecting
    posture exists to prevent. It went unnoticed because the original
    benchmark ran with an absolute repo_path, where os.path.join happens
    to discard the first argument and the bug cannot fire.

    Absolute reported paths are returned as-is; otherwise the path is
    tried as given (the common case) before falling back to joining it
    onto repo_path.
    """
    if os.path.isabs(reported_path):
        return reported_path if os.path.isfile(reported_path) else None
    for candidate in (reported_path, os.path.join(repo_path, reported_path)):
        if os.path.isfile(candidate):
            return candidate
    return None


def _line_has_nosemgrep_marker(repo_path: str, relative_file: str, line_no: int) -> bool:
    """Best-effort: read the exact reported line and check for ANY
    nosemgrep marker, regardless of which rule id it names.

    This deliberately does not try to match the marker's id against the
    firing rule's id. Consolidating registry rules into a new file (see
    build_registry_config) changes their effective check_id prefix from
    e.g. `python.lang.security.audit.dangerous-subprocess-use-audit` to
    whatever this repo's own config path resolves to -- so an existing
    `# nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit`
    comment, written when that rule was loaded from its original registry
    path, no longer id-matches the same rule loaded from our pruned
    config, and Semgrep's own nosemgrep handling silently stops
    suppressing it. Measured on this repo: 15 registry-layer findings,
    14 of which already carried a human-reviewed nosemgrep comment: with
    id-matching, 0 were suppressed; with this marker-only check, all 14
    were, correctly leaving the 1 finding nobody had reviewed yet."""
    path = _resolve_reported_path(repo_path, relative_file)
    if path is None:
        return False
    try:
        with open(path, errors="ignore") as fh:
            for i, line in enumerate(fh, start=1):
                if i == line_no:
                    return "nosemgrep" in line.lower() or "nosem" in line.lower()
    except OSError:
        pass
    return False


@dataclass
class LayeredScanResult:
    custom_findings: list[dict]
    registry_findings: list[dict]  # after the nosemgrep post-filter
    registry_findings_before_filter: int
    custom_config_path: str
    # One pruned config per detected language, not one per repo: a repo
    # with a Python backend and a TypeScript frontend needs both layers,
    # and scanning only the first-detected language silently drops the
    # other one's registry coverage.
    registry_configs: list[PrunedRegistryConfig] = field(default_factory=list)

    @property
    def registry_config_paths(self) -> list[str]:
        return [c.path for c in self.registry_configs]


def run_layered_scan(
    repo_path: str,
    custom_config_path: str,
    registry_root: str = DEFAULT_REGISTRY_ROOT,
    cache_dir: str | None = None,
) -> LayeredScanResult:
    """Run this repo's own custom pack and the pruned registry layer as
    two separate Semgrep invocations, in parallel, with different
    --disable-nosem policies, then merge.

    Why two invocations instead of one `--config` list: Semgrep's
    --disable-nosem is global to the whole invocation. There is no way to
    disable nosemgrep for one --config source and respect it for another
    within a single run. Given this pack's own stated posture (a
    compromised dependency or careless comment should not be able to
    blind OUR narrow, hard-to-game rules) needs to coexist with respecting
    a legitimate developer's prior triage of a broad, generic registry
    rule, two invocations is the only way to get both -- confirmed by
    testing the combined single-invocation form first and finding it
    couldn't express this at all.

    Runs both with subprocess in parallel (not sequentially) -- measured:
    sequential was slower than plain `semgrep --config=auto` on 2 of 3
    benchmark repos; parallel beat or matched it on all 3, since wall time
    becomes max(custom, registry) instead of their sum.

    Polyglot repos: every detected language gets its own pruned registry
    config, and the registry invocation is handed all of them at once.
    This stays one subprocess, not one per language -- the parallelism
    that matters here is custom-vs-registry, and splitting the registry
    layer further would just contend for the same cores."""
    import concurrent.futures
    import json as _json

    cache_dir = cache_dir or tempfile.mkdtemp(prefix="toleman-registry-")
    languages = detect_languages(repo_path)

    # Every detected language contributes its own pruned config. Kept as
    # separate --config files rather than merged into one: the registry
    # namespaces rule ids per language so there is nothing to dedupe
    # across them, and per-language files are what the cache is keyed on.
    registry_configs: list[PrunedRegistryConfig] = []
    for language in languages:
        technologies = detect_technologies(repo_path, language)
        pruned = build_registry_config(language, technologies, cache_dir, registry_root)
        if pruned and pruned.rule_count:
            registry_configs.append(pruned)

    def _run_custom() -> list[dict]:
        proc = subprocess.run(
            ["semgrep", "scan", f"--config={custom_config_path}", "--disable-nosem", "--json", "--quiet", repo_path],
            capture_output=True, text=True,
        )
        return _json.loads(proc.stdout or "{}").get("results", [])

    def _run_registry() -> list[dict]:
        if not registry_configs:
            return []
        config_args = [f"--config={c.path}" for c in registry_configs]
        proc = subprocess.run(
            ["semgrep", "scan", *config_args, "--json", "--quiet", repo_path],
            capture_output=True, text=True,
        )
        return _json.loads(proc.stdout or "{}").get("results", [])

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        custom_future = pool.submit(_run_custom)
        registry_future = pool.submit(_run_registry)
        custom_findings = custom_future.result()
        registry_findings_raw = registry_future.result()

    registry_findings = [
        r for r in registry_findings_raw
        if not _line_has_nosemgrep_marker(repo_path, r["path"], r["start"]["line"])
    ]

    return LayeredScanResult(
        custom_findings=custom_findings,
        registry_findings=registry_findings,
        registry_findings_before_filter=len(registry_findings_raw),
        custom_config_path=custom_config_path,
        registry_configs=registry_configs,
    )
