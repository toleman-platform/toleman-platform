"""Static registry of every OSS security tool Toleman knows about (issue #75).

This is deliberately a hardcoded Python list, not a DB table or a
YAML/JSON file loaded at runtime; the set of tools Toleman can actually run
is fixed by what `app.scanners.runner.TOOL_COMMANDS` and
`app.scanners.parsers.PARSER_MAP` know how to invoke/parse, so the registry
lives next to that code and stays in sync with it by construction (each
entry's `integrated` flag is computed from whether its `runner_key` is a
real TOOL_COMMANDS entry, not hand-maintained).

On installation: `install_cmd` is display-only text, and deliberately so;
it is a human-readable string, and handing a human-readable string to a
shell is how command injection happens.

One-click install (#216) is therefore built on `pip_package` instead, not on
`install_cmd`. The distinction is the whole security argument:

  * The API accepts a **registry key**, never a package name. `POST
    /api/tools/{tool}/install` looks `tool` up in this table and refuses
    anything not found, so a caller cannot name a package to install;
    only choose from this file. The set of installable things is fixed at
    deploy time by source code, not by request payloads.
  * The resulting command is assembled as an argv list from a constant
    (`[sys.executable, "-m", "pip", "install", ...]`) with the package
    appended as a single element. No shell, no string interpolation, no
    `shell=True`; same rule as `runner.clone_repo`'s allowlisted-host
    validation and its `--` before positional args.
  * `pip_package` is absent for tools that need brew/go/docker. Those are
    not installable from the running container at all, and the UI says so
    rather than offering a button that cannot work.

This is a narrower stance than #75's original blanket "no install from a web
request", not an abandonment of it: what was rejected was shelling out
arbitrary package-manager strings, and that is still rejected.
"""
from app.scanners.runner import TOOL_COMMANDS

# Tools int fully wired end-to-end (TOOL_COMMANDS -> parsers.PARSER_MAP ->
# ingestion) get category/usage metadata here. `tool` is the same string
# used as Scan.tool / Finding.tool / TOOL_COMMANDS key throughout the
# backend; keep them identical or every join by tool name breaks.
TOOL_REGISTRY = [
    {
        "tool": "semgrep",
        "display_name": "Semgrep",
        "category": "SAST",
        "languages": ["python", "javascript", "typescript", "go", "java", "ruby", "many more"],
        "description": "Static analysis for code-level vulnerabilities across most mainstream languages.",
        "install_cmd": "pip install semgrep",
        "docs_url": "https://semgrep.dev/docs/getting-started/",
        "version_cmd": ["semgrep", "--version"],
        "pip_package": "semgrep",
    },
    {
        "tool": "gitleaks",
        "display_name": "Gitleaks",
        "category": "Secrets",
        "languages": ["language-agnostic"],
        "description": "Detects hardcoded secrets and credentials in source and git history.",
        "install_cmd": "brew install gitleaks",
        "docs_url": "https://github.com/gitleaks/gitleaks#installing",
        "version_cmd": ["gitleaks", "version"],
    },
    {
        # (#255) Second secrets scanner, benchmarked against gitleaks,
        # trufflehog and detect-secrets on a 14-secret ground-truth corpus.
        # gitleaks stays the default on precision (100% precision, zero noise
        # on this repo); noseyparker is the recall option, 12/12 vs 11/12,
        # and the only one of the four with a rule for credentials embedded
        # in a Postgres connection URI, which is a real gap in what we ship.
        #
        # The cost is real and is why this is opt-in rather than default: on
        # a clean checkout of this repo noseyparker reports 26 findings to
        # gitleaks' 0, almost all test fixtures and migration passwords.
        "tool": "noseyparker",
        "display_name": "Nosey Parker",
        "category": "Secrets",
        "languages": ["language-agnostic"],
        "description": "High-recall secrets detection, including credentials embedded in connection URIs. Higher noise than Gitleaks, pair with FP rules.",
        "install_cmd": "brew install noseyparker",
        "docs_url": "https://github.com/praetorian-inc/noseyparker#usage",
        "version_cmd": ["noseyparker", "--version"],
    },
    {
        "tool": "trivy",
        "display_name": "Trivy",
        "category": "SCA",
        "languages": ["language-agnostic (dependency manifests + containers)"],
        "description": "Container image and filesystem vulnerability scanning (dependencies, OS packages).",
        "install_cmd": "brew install trivy",
        "docs_url": "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
        "version_cmd": ["trivy", "--version"],
    },
    {
        "tool": "trivy-license",
        "display_name": "Trivy (License scan)",
        "category": "License",
        "languages": ["language-agnostic"],
        "description": "License compliance scan over discovered dependencies, using Trivy's license scanner mode.",
        "install_cmd": "brew install trivy",
        "docs_url": "https://aquasecurity.github.io/trivy/latest/docs/scanner/license/",
        "version_cmd": ["trivy", "--version"],
    },
    {
        "tool": "gosec",
        "display_name": "gosec",
        "category": "SAST",
        "languages": ["go"],
        "description": "Go-specific static analysis security scanner.",
        "install_cmd": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
        "docs_url": "https://github.com/securego/gosec#install",
        "version_cmd": ["gosec", "--version"],
    },
    {
        "tool": "checkov",
        "display_name": "Checkov",
        "category": "IaC",
        "languages": ["terraform", "cloudformation", "kubernetes", "dockerfile", "arm", "bicep"],
        "description": "Infrastructure-as-code misconfiguration scanning across Terraform, CloudFormation, Kubernetes manifests, and more.",
        "install_cmd": "pip install checkov",
        "docs_url": "https://www.checkov.io/2.Basics/Installing%20Checkov.html",
        "version_cmd": ["checkov", "--version"],
        "pip_package": "checkov",
    },
    {
        "tool": "tfsec",
        "display_name": "tfsec",
        "category": "IaC",
        "languages": ["terraform"],
        "description": "Terraform-focused static analysis for cloud misconfigurations.",
        "install_cmd": "brew install tfsec  # macOS host; in a container: curl -sSL https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash",
        "docs_url": "https://aquasecurity.github.io/tfsec/latest/guides/installation/",
        "version_cmd": ["tfsec", "--version"],
    },
    # AI/ML security tooling (issue #187). All catalog-only, same status as
    # kics below: registered for visibility + health-check, no TOOL_COMMANDS
    # entry, so `integrated` computes False and default_usage_for() forces
    # every usage surface off. Integration is tracked separately (#185 for
    # AI-repo detection, #186 for modelscan) so the catalog can be useful
    # before any of it is wired up.
    {
        "tool": "modelscan",
        "display_name": "ModelScan",
        "category": "AI/ML",
        "languages": ["python (pickle, joblib, dill)", "pytorch", "tensorflow", "keras"],
        "description": "Scans serialized model files for unsafe deserialization. Loading a pickled model executes code, so a hostile .pkl/.pt is RCE at load time with no exploit chain, ordinary SAST never looks at binary weights. Runs only against repos detected as AI/ML (#185).",
        "install_cmd": "pip install 'modelscan[tensorflow,h5py]'",
        "docs_url": "https://github.com/protectai/modelscan#getting-started",
        "version_cmd": ["modelscan", "-v"],
        "pip_package": "modelscan[tensorflow,h5py]",
    },
    {
        "tool": "semgrep-llm",
        "display_name": "Semgrep (LLM rules)",
        "category": "AI/ML",
        "languages": ["python"],
        "description": "Toleman's curated OWASP LLM Top 10 ruleset: LLM output reaching eval/shell/SQL sinks, unsafe model deserialization, and unpinned Hugging Face model references. Runs the Semgrep engine against rules shipped in-repo, not a hosted registry, so results are reproducible offline. Only runs on repos detected as AI/ML (#185).",
        "install_cmd": "pip install semgrep",
        "docs_url": "https://semgrep.dev/docs/writing-rules/rule-syntax/",
        "version_cmd": ["semgrep", "--version"],
        "pip_package": "semgrep",
    },
    {
        "tool": "garak",
        "display_name": "garak",
        "category": "AI/ML",
        "languages": ["language-agnostic (probes a live model endpoint)"],
        "description": "LLM red-teaming: prompt injection, jailbreaks, data leakage, toxic output. Unlike every other tool here it needs a live model endpoint rather than a checkout, so it belongs with #72's active API scanning rather than the repo-scanner path. Results are non-deterministic, which the finding model would have to account for.",
        "install_cmd": "python -m pip install -U garak",
        "docs_url": "https://github.com/NVIDIA/garak#getting-started",
        "version_cmd": ["garak", "--version"],
        "pip_package": "garak",
    },
    {
        "tool": "medusa",
        "display_name": "MEDUSA",
        "category": "AI/ML",
        "languages": ["python", "javascript", "typescript", "go", "rust", "php", "many more"],
        "description": "AI-first SAST with rules for agentic AI, MCP servers and RAG pipelines (OWASP LLM Top 10), plus scanning of agent config files. NOTE: AGPL-3.0-or-later, the only copyleft-with-network-clause tool in this registry, so bundling it is a deliberate licensing decision, not a default. Young project (created 2025-11) and effectively single-maintainer; evaluate before running it against user code.",
        "install_cmd": "pip install medusa-security",
        "docs_url": "https://github.com/Pantheon-Security/medusa#readme",
        "version_cmd": ["medusa", "--version"],
        "pip_package": "medusa-security",
    },
    {
        "tool": "snyk-agent-scan",
        "display_name": "Snyk Agent Scan",
        "category": "AI/ML",
        "languages": ["language-agnostic (MCP server + agent skill manifests)"],
        "description": "Scans MCP servers and agent skills for prompt injection, tool poisoning and rug pulls. Formerly Invariant Labs' mcp-scan; the `mcp-scan` PyPI package is deprecated and redirects here. Directly relevant to Toleman's own MCP server (#108).",
        "install_cmd": "pip install snyk-agent-scan",
        "docs_url": "https://github.com/snyk/agent-scan#readme",
        "version_cmd": ["snyk-agent-scan", "--version"],
        "pip_package": "snyk-agent-scan",
    },
    {
        "tool": "cisco-aibom",
        "display_name": "Cisco AIBOM",
        "category": "AI/ML",
        "languages": ["python", "language-agnostic (source-code scan)"],
        "description": "Generates an AI Bill of Materials from source, models, datasets and lineage, the parts a conventional SBOM is blind to. Complements the CycloneDX SBOM Trivy already produces rather than replacing it.",
        "install_cmd": "pip install cisco-aibom",
        "docs_url": "https://github.com/cisco-ai-defense/aibom#readme",
        "version_cmd": ["cisco-aibom", "--version"],
        "pip_package": "cisco-aibom",
    },
    {
        "tool": "kics",
        "display_name": "KICS",
        "category": "IaC",
        "languages": ["terraform", "kubernetes", "cloudformation", "dockerfile", "ansible", "many more"],
        "description": "Broad IaC misconfiguration scanner (Checkmarx). Registered for visibility/health-check; native scan execution isn't wired up yet, track as a follow-up once there's real parser coverage for its JSON output.",
        "install_cmd": "docker pull checkmarx/kics",
        "docs_url": "https://docs.kics.io/latest/getting-started/",
        "version_cmd": ["kics", "version"],
    },
    # (#232) The mirror image of kics above: nuclei genuinely executes;
    # Active API Scanning (#72) has run it unconditionally since it shipped,
    # but through app.scanners.runner.run_nuclei() and
    # app.scanners.parsers.parse_nuclei(), a dedicated path outside
    # TOOL_COMMANDS/PARSER_MAP, because its invocation takes a list of live
    # discovered URLs rather than a repo-path checkout like every other
    # entry here. That means it can never appear in runnable_tools() or a
    # tools_for_surface() result no matter what; see
    # app.core.tool_usage.is_nuclei_enabled_for_api_scan, the dedicated
    # single-tool check api_scan.py actually calls, and
    # default_usage_for's docstring for why api_scan defaults True here
    # specifically (preserving existing behavior) while every other surface
    # correctly defaults False (nuclei cannot run in any of them).
    #
    # Registered mainly so this workspace-level toggle has a real row to
    # live on in Tool Marketplace, not to gain an install button: nuclei is
    # a Go binary, not pip-installable, so no `pip_package` is set and the
    # copyable command stays the only install path (matching the "a button
    # that cannot work is worse than no button" rule already documented on
    # the marketplace page for every other non-pip tool).
    {
        "tool": "nuclei",
        "display_name": "Nuclei",
        "category": "API/DAST",
        "languages": ["language-agnostic (live HTTP endpoints)"],
        "description": "Active scanning against already-discovered API endpoints (#72), misconfigurations, default logins, known-CVE templates. The only tool this platform runs against a live target rather than a repo checkout. Controls the API scan toggle below; has no effect on the other three surfaces.",
        "install_cmd": "brew install nuclei",
        "docs_url": "https://docs.projectdiscovery.io/tools/nuclei/install",
        "version_cmd": ["nuclei", "-version"],
    },
]

# Usage-assignment surfaces a tool can be turned on/off for, per workspace
# (issue #75's "per-tool usage assignment"). Kept as a plain tuple rather
# than an Enum so app/api/tools.py's WorkspaceToolConfig payload validation
# and the frontend's toggle list share one literal source without an extra
# import surface, WorkspaceToolConfig itself declares the four columns
# explicitly (see models.py), this tuple is only for validating which
# field names a PUT may target.
USAGE_SURFACES = ("on_demand_scan", "ci_pipeline", "api_scan", "pr_guardrail")


# Tools the shipped backend image installs, so a fresh `docker compose up`
# can scan without an operator installing anything (#75, #186).
#
# This is a contract, not documentation: `backend/scripts/verify_tools.py`
# runs each of these tools' `version_cmd` *inside the built image* in CI and
# fails if one is missing. Without that, a Dockerfile edit or a dependency
# resolving differently can quietly ship an image whose scanner is gone;
# which is not a loud failure at build time, it is a scan that returns zero
# findings at runtime and reads exactly like a clean repo.
#
# Everything else in the registry is genuinely optional and installed on
# demand (see install.py); absent is its honest state, not a defect.
BUNDLED_TOOLS = frozenset(
    {"semgrep", "semgrep-llm", "gitleaks", "trivy", "trivy-license", "gosec", "modelscan"}
)


def default_usage_for(tool: str) -> dict:
    """Built-in usage-surface defaults for a tool with no saved
    WorkspaceToolConfig row (issue #75). Mirrors WorkspaceToolConfig's own
    column defaults for an *integrated* tool (on-demand/CI/PR guardrail on)
    but forces every surface off for a registry-only tool like kics that has
    no real TOOL_COMMANDS entry; there is nothing to "run" for it yet, so
    defaulting it to enabled would be a silent no-op that misleads an admin
    into thinking it's active.

    (#232) api_scan defaults False for every tool except nuclei, which is
    the mirror-image special case: nuclei is genuinely not a TOOL_COMMANDS
    entry (its invocation takes a URL list from Active API Scanning's own
    discovered-endpoints flow, app.core.api_scan_targets; nothing like the
    repo-path shape every other tool shares), so `integrated` above is False
    for it and it can never appear in tools_for_surface's runnable_tools()
    intersection. But active API scanning has run unconditionally since #72
    shipped, gated only on api_base_url being configured; so defaulting
    api_scan off for nuclei the day this ships would silently turn off a
    feature every existing user already has on. See
    app.core.tool_usage.is_nuclei_enabled_for_api_scan, which resolves this
    the same saved-row-else-default way as tools_for_surface but without
    routing through runnable_tools(), since nuclei structurally can't pass
    that check.
    """
    integrated = tool in TOOL_COMMANDS
    return {
        "on_demand_scan": integrated,
        "ci_pipeline": integrated,
        "api_scan": tool == "nuclei",
        "pr_guardrail": integrated,
    }


# Real Finding.tool values that never appear in TOOL_REGISTRY at all, so
# tool_category() below still needs to know about them:
#   * "api-scan" -- app/tasks/api_scan_tasks.py deliberately tags every
#     nuclei-sourced finding "api-scan", not "nuclei" (nuclei itself is
#     registered above for Tool Marketplace/health-check purposes, but no
#     Finding row is ever persisted with tool="nuclei").
#   * "osv-malware" -- app/core/osv_malware_ingestion.py writes malicious-
#     package Finding rows directly, bypassing app.core.ingestion.ingest_findings
#     (and therefore this registry) entirely.
_EXTRA_TOOL_CATEGORIES = {
    "api-scan": "API/DAST",
    "osv-malware": "Malicious Package",
}

# The category a Finding's tool is grouped/filtered under (Findings page)
# when it matches neither TOOL_REGISTRY nor _EXTRA_TOOL_CATEGORIES above --
# notably, `POST /api/ingest/{target_id}` (a CI pipeline's own SARIF upload)
# accepts any caller-supplied `tool` string, so this is a real, reachable
# case, not just future-proofing.
UNKNOWN_TOOL_CATEGORY = "Other"


def tool_category(tool: str) -> str:
    """The vulnerability-type category (Findings page grouping/filter, issue
    tracker request) for a Finding's `tool` string. Sourced from
    TOOL_REGISTRY's own per-tool `category` -- the same vocabulary Tool
    Marketplace already shows users ("SAST", "SCA", "Secrets", "IaC",
    "License", "API/DAST", "AI/ML") -- rather than a second, drifting
    category list; plus the handful of real Finding.tool values that never
    appear in TOOL_REGISTRY at all (see _EXTRA_TOOL_CATEGORIES)."""
    for entry in TOOL_REGISTRY:
        if entry["tool"] == tool:
            return entry["category"]
    return _EXTRA_TOOL_CATEGORIES.get(tool, UNKNOWN_TOOL_CATEGORY)


def all_known_tools() -> list[str]:
    """Every tool name tool_category() maps to a real (non-"Other")
    category. Used to build the SQL exclusion for filtering Findings by the
    "Other" category itself: NOT IN this set, rather than hand-maintaining a
    second list."""
    return [entry["tool"] for entry in TOOL_REGISTRY] + list(_EXTRA_TOOL_CATEGORIES.keys())


def tools_in_category(category: str) -> list[str]:
    """Tool names belonging to `category`, for filtering Findings by
    category at the SQL level (Finding.tool.in_(...)) -- category is purely
    derived from tool, so there is nothing to store or join, just the
    reverse of tool_category(). Empty list for "Other" (see
    all_known_tools()/UNKNOWN_TOOL_CATEGORY instead: that one needs a NOT
    IN, not an IN)."""
    tools = [entry["tool"] for entry in TOOL_REGISTRY if entry["category"] == category]
    tools += [t for t, c in _EXTRA_TOOL_CATEGORIES.items() if c == category]
    return tools


def all_categories() -> list[str]:
    """Every category a Finding could be grouped under, sorted, for the
    Findings page's filter dropdown."""
    cats = {entry["category"] for entry in TOOL_REGISTRY} | set(_EXTRA_TOOL_CATEGORIES.values())
    cats.add(UNKNOWN_TOOL_CATEGORY)
    return sorted(cats)


def registry_with_integration_status() -> list[dict]:
    """Registry entries plus a computed `integrated` flag; True only when
    the tool has a real TOOL_COMMANDS entry (i.e. Toleman can actually execute
    a scan for it today), False for registry-only/health-check-only tools
    like kics above."""
    out = []
    for entry in TOOL_REGISTRY:
        out.append(
            {
                **entry,
                "integrated": entry["tool"] in TOOL_COMMANDS,
                # (docs-drift item 6) Whether the shipped image already
                # carries this tool. An external review pointed out the
                # marketplace showed `brew install gitleaks` to an admin
                # operating a Debian container; where brew does not exist,
                # and where gitleaks was already installed anyway. For a
                # bundled tool the install command is not just wrong for the
                # platform, it is answering a question that does not apply.
                "bundled": entry["tool"] in BUNDLED_TOOLS,
                # (#216) Whether the one-click install button applies. Derived
                # from pip_package rather than hand-flagged, so a tool cannot
                # advertise a button the install path would then refuse.
                "installable": bool(entry.get("pip_package")),
            }
        )
    return out
