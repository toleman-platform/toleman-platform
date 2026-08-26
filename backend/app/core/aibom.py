"""AI Bill of Materials generation (issue #190).

An ordinary SBOM inventories *packages*. It will tell you a repo depends on
`transformers==4.44.0` and nothing whatsoever about which model that code
pulls at runtime, from where, at what revision, or under what licence. On an
AI repo that is where most of the real supply-chain risk lives, so an AIBOM
inventories models and datasets alongside the packages.

Format is CycloneDX 1.6, which added first-class machine-learning component
types. Chosen over SPDX 3.0's AI profile for one practical reason: this
codebase already exports CycloneDX from its persisted SbomComponent rows, so
an AIBOM extends the pipeline that exists rather than introducing a second
format and a second parser. SPDX has ISO lineage that
carries weight in procurement and is the obvious second target, but building
both at once would be speculative.

Extraction is hand-rolled rather than delegated to `cisco-aibom`. That
package was evaluated first and rejected on deployment cost: it requires
libcst>=1.0.0, which ships no wheel for this platform and needs a Rust
toolchain to build from source. Adding a Rust build step to the backend image
is a poor trade for a project whose largest adoption blocker was deployment
(#60), especially when the extraction itself is a few regexes over source.

THE HONEST CAVEAT, which shapes the whole module: model and dataset lineage
is frequently NOT declarable from source. A repo calling
`openai.chat.completions.create(model="gpt-5")` has a real model dependency
with no accessible training-data provenance and no version to pin. Those
facts are emitted as explicit "unknown", never omitted and never guessed. A
compliance artifact that silently implies full provenance is a liability, not
a feature; the same principle as #174's never-scanned repos showing no
verdict rather than a green one.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.ai_repo_detection import SKIP_DIRECTORIES
from app.core.time import utcnow

CYCLONEDX_SPEC_VERSION = "1.6"
CYCLONEDX_BOM_FORMAT = "CycloneDX"

# Value used wherever provenance genuinely can't be determined from source.
# Deliberately a visible string rather than null or an omitted key: a reader
# scanning the document must be able to see that the field was considered and
# came back unknown, not assume it was fine.
UNKNOWN = "unknown"

_SOURCE_SUFFIXES = frozenset({".py", ".js", ".ts", ".tsx", ".jsx", ".ipynb", ".yaml", ".yml", ".toml"})

# Hugging Face repo ids: "org/name", optionally with a revision kwarg nearby.
_HF_FROM_PRETRAINED = re.compile(
    r"""from_pretrained\(\s*["']([A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+)["']"""
)
_HF_HUB_DOWNLOAD = re.compile(
    r"""(?:hf_hub_download|snapshot_download)\([^)]*repo_id\s*=\s*["']([A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+)["']""",
    re.DOTALL,
)
# revision="..." appearing in the same call, used to decide pinned vs not.
_REVISION = re.compile(r"""revision\s*=\s*["']([A-Za-z0-9._\-]+)["']""")


def _revision_in_call(text: str, start: int) -> str:
    """Find a `revision=` kwarg belonging to the call that starts at `start`.

    Bounded to the call's own closing paren. An earlier version scanned a
    fixed 400-character window forward, which bled into the *next* statement:
    given

        m   = AutoModel.from_pretrained('org/a')
        pin = AutoModel.from_pretrained('org/b', revision='abc123')

    it reported org/a as pinned to abc123; inventing provenance for an
    unpinned model, which is the single worst thing this module could do.
    """
    close = text.find(")", start)
    window = text[start : close if close != -1 else start + 400]
    match = _REVISION.search(window)
    return match.group(1) if match else UNKNOWN

# Hosted-model references: model="gpt-5" / model='claude-...' on an API call.
_HOSTED_MODEL = re.compile(r"""\bmodel\s*[=:]\s*["']([A-Za-z0-9._\-:]{2,80})["']""")

# Datasets loaded via the HF datasets library.
_DATASET = re.compile(r"""load_dataset\(\s*["']([A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)?)["']""")

# Hosted model names are matched by a permissive regex, so this filters the
# obvious non-models it would otherwise sweep up (a `model=` kwarg on an ORM
# call, a Pydantic config, etc.). Prefix match, lowercased.
_HOSTED_MODEL_PREFIXES = (
    "gpt-", "gpt", "o1", "o3", "o4", "chatgpt",
    "claude", "gemini", "palm", "mistral", "mixtral", "llama", "codellama",
    "command", "deepseek", "qwen", "phi-", "grok", "titan", "jamba", "nova-",
    "text-embedding", "text-davinci", "whisper", "dall-e", "sonar",
)


@dataclass
class AiComponent:
    """One model or dataset in the AIBOM."""

    name: str
    component_type: str  # "machine-learning-model" | "data"
    version: str = UNKNOWN
    source: str = UNKNOWN  # where it comes from: huggingface, hosted-api, local
    evidence: list[str] = field(default_factory=list)  # files it was found in

    def bom_ref(self) -> str:
        return f"{self.component_type}:{self.name}@{self.version}"


def _iter_source_files(repo_path: Path):
    for path in repo_path.rglob("*"):
        try:
            rel = path.relative_to(repo_path)
        except ValueError:
            continue
        if any(part in SKIP_DIRECTORIES for part in rel.parts[:-1]):
            continue
        if path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES:
            yield path, rel


def _strip_comment_lines(text: str) -> str:
    """Blank out whole-line comments before matching.

    The model-name regex is text-based, so without this it matches names
    mentioned in prose. Caught immediately: running the extractor over this
    codebase pulled "gpt-5" and "claude-..." out of *this module's own
    comments*, which would have shipped an AIBOM claiming Toleman depends on
    models it only talks about. On a real repo the same thing happens with a
    docstring or a TODO mentioning a model name.

    Whole-line comments only. A trailing comment after real code is left
    alone, since the code on that line is worth matching, and stripping
    mid-line would need a real parser rather than a heuristic; the cost of
    a rare extra reference is a duplicate inventory row, not a wrong one.

    KNOWN LIMITATION: triple-quoted docstrings are not stripped, so a
    docstring containing a literal model reference is still matched. Catching
    those would need a real AST parse per language, which is a large cost for
    a rare case. The `evidence` field on every component names the file it
    came from, so an over-inclusive row is visible and dismissible rather
    than silent; which is the right failure direction for an inventory: a
    reviewable extra beats a missing dependency.
    """
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "--")):
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


def _looks_like_hosted_model(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(_HOSTED_MODEL_PREFIXES)


def extract_ai_components(repo_path: str | Path) -> list[AiComponent]:
    """Scan a checkout for model and dataset references.

    Returns components keyed by (name, type), merging evidence across files.
    A model referenced with no pinned revision gets version=UNKNOWN; that
    is the finding, not a gap to paper over.
    """
    root = Path(repo_path)
    if not root.is_dir():
        return []

    found: dict[tuple[str, str], AiComponent] = {}

    def _record(name: str, component_type: str, source: str, version: str, rel: Path):
        key = (name, component_type)
        existing = found.get(key)
        if existing is None:
            found[key] = AiComponent(
                name=name,
                component_type=component_type,
                version=version,
                source=source,
                evidence=[str(rel)],
            )
            return
        if str(rel) not in existing.evidence:
            existing.evidence.append(str(rel))
        # A pinned reference anywhere beats an unpinned one: the repo does
        # demonstrably pin it somewhere, which is the more useful fact.
        if existing.version == UNKNOWN and version != UNKNOWN:
            existing.version = version

    for path, rel in _iter_source_files(root):
        try:
            text = _strip_comment_lines(path.read_text(errors="ignore"))
        except OSError:
            continue

        for match in _HF_FROM_PRETRAINED.finditer(text):
            name = match.group(1)
            _record(name, "machine-learning-model", "huggingface", _revision_in_call(text, match.start()), rel)

        for match in _HF_HUB_DOWNLOAD.finditer(text):
            name = match.group(1)
            _record(name, "machine-learning-model", "huggingface", _revision_in_call(text, match.start()), rel)

        for match in _HOSTED_MODEL.finditer(text):
            name = match.group(1)
            if _looks_like_hosted_model(name):
                # A hosted API model has no pinnable revision from the
                # caller's side; the provider can change what sits behind
                # the name. That is exactly the kind of thing an AIBOM
                # exists to make visible.
                _record(name, "machine-learning-model", "hosted-api", UNKNOWN, rel)

        for match in _DATASET.finditer(text):
            _record(match.group(1), "data", "huggingface", UNKNOWN, rel)

    return sorted(found.values(), key=lambda c: (c.component_type, c.name))


def _component_to_cyclonedx(component: AiComponent) -> dict:
    entry = {
        "type": component.component_type,
        "bom-ref": component.bom_ref(),
        "name": component.name,
        "version": component.version,
        "properties": [
            {"name": "toleman:source", "value": component.source},
            {"name": "toleman:evidence", "value": ", ".join(component.evidence[:10])},
        ],
    }

    if component.component_type == "machine-learning-model":
        # CycloneDX 1.6 modelCard. Every field here is genuinely unknown from
        # static analysis, and saying so explicitly is the point; an absent
        # modelCard reads as "not applicable", which is a different and
        # wrong claim.
        entry["modelCard"] = {
            "bom-ref": f"modelcard:{component.bom_ref()}",
            "modelParameters": {
                "task": UNKNOWN,
                "architectureFamily": UNKNOWN,
                "datasets": [{"type": "other", "name": UNKNOWN}],
            },
            "considerations": {
                "technicalLimitations": [
                    "Provenance not determinable from source: training data, model lineage "
                    "and licence were not declared in this repository."
                ]
            },
        }

    if component.version == UNKNOWN:
        entry["properties"].append(
            {
                "name": "toleman:unpinned",
                "value": "true",
            }
        )
    return entry


def build_aibom(
    components: list[AiComponent],
    target_name: str,
    repo_url: str = "",
    branch: str = "",
    timestamp: str | None = None,
) -> dict:
    """Assemble a CycloneDX 1.6 document.

    `timestamp` is injected rather than generated so callers own it and the
    output is deterministic under test.
    """
    metadata: dict = {
        "component": {
            "type": "application",
            "bom-ref": f"target:{target_name}",
            "name": target_name,
        },
        "tools": {"components": [{"type": "application", "name": "toleman", "publisher": "toleman"}]},
    }
    if timestamp:
        metadata["timestamp"] = timestamp
    if repo_url:
        metadata["component"]["externalReferences"] = [{"type": "vcs", "url": repo_url}]
    if branch:
        metadata["properties"] = [{"name": "toleman:branch", "value": branch}]

    return {
        "bomFormat": CYCLONEDX_BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": [_component_to_cyclonedx(c) for c in components],
    }


def aibom_summary(components: list[AiComponent]) -> dict:
    """Counts for the UI. `unpinned` is the number a reader should act on."""
    models = [c for c in components if c.component_type == "machine-learning-model"]
    datasets = [c for c in components if c.component_type == "data"]
    return {
        "models": len(models),
        "datasets": len(datasets),
        "unpinned": sum(1 for c in components if c.version == UNKNOWN),
        "hosted_api_models": sum(1 for c in models if c.source == "hosted-api"),
    }


def upsert_aibom_components(
    session,
    target_id: int,
    branch: str,
    components: list[AiComponent],
) -> list:
    """Persist extracted components, mirroring
    app.core.sbom_ingestion.upsert_components. Returns the net-new rows.

    Keyed on (target, branch, name, type); deliberately not including
    version. An unpinned reference that later gains a revision is the *same*
    dependency, now pinned; treating it as a new component would hide exactly
    the change a reader most wants to see.
    """
    from datetime import UTC, datetime

    from sqlmodel import select

    from app.models.models import AiBomComponent

    existing = {
        (row.name, row.component_type): row
        for row in session.exec(
            select(AiBomComponent).where(
                AiBomComponent.target_id == target_id, AiBomComponent.branch == branch
            )
        ).all()
    }

    now = utcnow()
    new_rows = []
    for component in components:
        key = (component.name, component.component_type)
        evidence = ", ".join(component.evidence[:10])
        row = existing.get(key)
        if row is None:
            row = AiBomComponent(
                target_id=target_id,
                branch=branch,
                name=component.name,
                component_type=component.component_type,
                version=component.version,
                source=component.source,
                evidence=evidence,
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
            new_rows.append(row)
            continue

        row.version = component.version
        row.source = component.source
        row.evidence = evidence
        row.last_seen = now
        session.add(row)

    session.commit()
    for row in new_rows:
        session.refresh(row)
    return new_rows
