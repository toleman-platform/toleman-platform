"""AI/ML repo detection (issue #185): the gate every AI-specific scanner
in epic #192 runs behind.

Why detect rather than let an admin flag it: an explicit per-target toggle
was considered and rejected, because somebody has to remember to set it and
an *unflagged* AI repo then silently gets zero AI coverage. Silent
non-coverage is the exact failure mode the AI scanners exist to prevent, so
the default has to be "the platform works it out". A manual override still
wins where it's been set (see Target.is_ai_repo_override); auto-detection
is the default, not a straitjacket.

Two independent signals, either sufficient:

  1. Model artifacts present in the checkout (by extension).
  2. AI/ML packages in the target's already-persisted SbomComponent
     inventory, a DB query, not a re-parse of the manifests, since
     app.core.sbom_ingestion already stores name/version/package_type per
     target+branch.

Detection returns *which* signals fired, not just a boolean. "Detected
because torch is a dependency" is what makes the result debuggable and lets
a user argue with it; a bare True is not contestable.
"""
from dataclasses import dataclass, field
from pathlib import Path

# Serialized-model extensions. Deliberately the same set #186's modelscan
# integration cares about; if a file here is present, that scanner has
# something real to look at.
MODEL_FILE_EXTENSIONS = frozenset(
    {
        ".pkl",
        ".pickle",
        ".pt",
        ".pth",
        ".bin",
        ".safetensors",
        ".h5",
        ".keras",
        ".onnx",
        ".pb",
        ".gguf",
        ".ggml",
        ".joblib",
        ".dill",
    }
)

# Directories never walked. On a repo with 1351 npm components a naive
# os.walk is pathological, and a model file vendored inside node_modules or
# a virtualenv belongs to a dependency, not to this repo.
SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".tox",
        "vendor",
        "target",
        ".mypy_cache",
        ".pytest_cache",
    }
)

# AI/ML package names by ecosystem. Matching is exact on the lowercased
# package name except where a prefix is noted below; a substring match
# would flag any package merely containing "ai", which is most of npm.
_PY_PACKAGES = frozenset(
    {
        # frameworks
        "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-cpu",
        "keras", "jax", "jaxlib", "scikit-learn", "sklearn", "xgboost",
        "lightgbm", "catboost", "onnx", "onnxruntime",
        # LLM / agent
        "openai", "anthropic", "transformers", "sentence-transformers",
        "huggingface-hub", "diffusers", "accelerate", "peft", "trl",
        "llama-index", "llama-cpp-python", "vllm", "ollama", "litellm",
        "haystack-ai", "crewai", "autogen", "pyautogen", "guidance", "dspy-ai",
        "instructor", "outlines", "cohere", "replicate", "together",
        "google-generativeai", "mistralai", "groq",
        # vector stores / RAG
        "chromadb", "pinecone-client", "pinecone", "weaviate-client",
        "qdrant-client", "faiss-cpu", "faiss-gpu", "lancedb", "pymilvus",
        # serving / experiment tracking
        "mlflow", "bentoml", "kserve", "wandb", "sagemaker",
    }
)

# Python packages matched by prefix; these are real namespace families
# (langchain-core, langchain-openai, ...) rather than a loose contains-check.
_PY_PREFIXES = ("langchain", "llama-index-", "opentelemetry-instrumentation-openai")

_NPM_PACKAGES = frozenset(
    {
        "openai", "anthropic", "@anthropic-ai/sdk", "ai", "cohere-ai",
        "replicate", "langchain", "llamaindex", "@huggingface/inference",
        "@huggingface/transformers", "@xenova/transformers",
        "@google/generative-ai", "@mistralai/mistralai", "groq-sdk",
        "onnxruntime-node", "onnxruntime-web", "@tensorflow/tfjs",
        "@tensorflow/tfjs-node", "chromadb", "@pinecone-database/pinecone",
        "weaviate-ts-client", "@qdrant/js-client-rest", "ollama",
    }
)

_NPM_PREFIXES = ("@langchain/", "@llamaindex/", "@ai-sdk/")

_GO_SUBSTRINGS = (
    "github.com/sashabaranov/go-openai",
    "github.com/tmc/langchaingo",
    "github.com/anthropics/anthropic-sdk-go",
    "github.com/ollama/ollama",
)


@dataclass
class AiRepoDetection:
    """Result of a detection pass. `signals` is the human-readable reason
    list; empty exactly when `detected` is False."""

    detected: bool = False
    signals: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"detected": self.detected, "signals": list(self.signals)}


def _package_matches(name: str, package_type: str) -> bool:
    """Is this dependency an AI/ML one? `package_type` is Trivy's, as stored
    on SbomComponent (npm / pip / gomod on real data)."""
    lowered = name.strip().lower()
    if not lowered:
        return False

    if package_type == "npm":
        return lowered in _NPM_PACKAGES or lowered.startswith(_NPM_PREFIXES)
    if package_type in ("pip", "python-pkg", "poetry", "conda"):
        return lowered in _PY_PACKAGES or lowered.startswith(_PY_PREFIXES)
    if package_type in ("gomod", "golang"):
        return any(s in lowered for s in _GO_SUBSTRINGS)

    # Unknown ecosystem: fall back to the Python list, which is where most
    # ML tooling lives. Better a possible extra signal than a silent miss.
    return lowered in _PY_PACKAGES or lowered.startswith(_PY_PREFIXES)


def detect_model_files(repo_path: str | Path, max_reported: int = 5) -> list[str]:
    """Repo-relative paths of serialized model files, capped at
    `max_reported` for the signal list (the count is what matters, not an
    exhaustive listing). Walks the checkout once, skipping SKIP_DIRECTORIES.
    """
    root = Path(repo_path)
    if not root.is_dir():
        return []

    found: list[str] = []
    for path in root.rglob("*"):
        if len(found) >= max_reported:
            break
        try:
            if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts[:-1]):
                continue
            if path.is_file() and path.suffix.lower() in MODEL_FILE_EXTENSIONS:
                found.append(str(path.relative_to(root)))
        except (OSError, ValueError):
            # Broken symlink, permission error, or a path that escaped the
            # root; skip it rather than failing the whole detection pass.
            continue
    return found


def detect_ai_packages(components: list[tuple[str, str]], max_reported: int = 5) -> list[str]:
    """AI/ML package names among `components`, a list of (name,
    package_type); i.e. SbomComponent rows the caller already has."""
    matched: list[str] = []
    seen: set[str] = set()
    for name, package_type in components:
        if len(matched) >= max_reported:
            break
        key = (name or "").strip().lower()
        if key in seen:
            continue
        if _package_matches(name or "", (package_type or "").lower()):
            seen.add(key)
            matched.append(name)
    return matched


def detect_ai_repo(
    repo_path: str | Path | None = None,
    components: list[tuple[str, str]] | None = None,
) -> AiRepoDetection:
    """Run both signals. Either one alone is sufficient.

    `repo_path` is optional so detection can be re-run from persisted SBOM
    inventory alone, without a checkout; useful for re-evaluating every
    target without cloning 35 repos.
    """
    signals: list[str] = []

    if repo_path is not None:
        model_files = detect_model_files(repo_path)
        if model_files:
            signals.append(f"model files present: {', '.join(model_files)}")

    if components:
        packages = detect_ai_packages(components)
        if packages:
            signals.append(f"AI/ML dependencies: {', '.join(packages)}")

    return AiRepoDetection(detected=bool(signals), signals=signals)
