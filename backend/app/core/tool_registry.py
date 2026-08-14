"""Static registry of every OSS security tool OSP knows about (issue #75).

This is deliberately a hardcoded Python list, not a DB table or a
YAML/JSON file loaded at runtime -- the set of tools OSP can actually run
is fixed by what `app.scanners.runner.TOOL_COMMANDS` and
`app.scanners.parsers.PARSER_MAP` know how to invoke/parse, so the registry
lives next to that code and stays in sync with it by construction (each
entry's `integrated` flag is computed from whether its `runner_key` is a
real TOOL_COMMANDS entry, not hand-maintained).

Deliberately NOT a "one-click install that shells out to apt/brew/pip on
the request thread" -- running arbitrary package-manager commands triggered
from a web request is a real command-injection/RCE surface for a security
tool to carry, so `install_cmd` here is display-only text for an admin to
copy and run themselves (or bake into their scanner image/Dockerfile), same
spirit as `runner.clone_repo`'s allowlisted-host validation: never hand
attacker- or admin-influenced strings straight to a shell. See PR
description for #75 -- this is the one point flagged for a human
check-in rather than being auto-implemented as literal remote install.
"""
from app.scanners.runner import TOOL_COMMANDS

# Tools int fully wired end-to-end (TOOL_COMMANDS -> parsers.PARSER_MAP ->
# ingestion) get category/usage metadata here. `tool` is the same string
# used as Scan.tool / Finding.tool / TOOL_COMMANDS key throughout the
# backend -- keep them identical or every join by tool name breaks.
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
    },
    {
        "tool": "tfsec",
        "display_name": "tfsec",
        "category": "IaC",
        "languages": ["terraform"],
        "description": "Terraform-focused static analysis for cloud misconfigurations.",
        "install_cmd": "brew install tfsec",
        "docs_url": "https://aquasecurity.github.io/tfsec/latest/guides/installation/",
        "version_cmd": ["tfsec", "--version"],
    },
    {
        "tool": "kics",
        "display_name": "KICS",
        "category": "IaC",
        "languages": ["terraform", "kubernetes", "cloudformation", "dockerfile", "ansible", "many more"],
        "description": "Broad IaC misconfiguration scanner (Checkmarx). Registered for visibility/health-check; native scan execution isn't wired up yet -- track as a follow-up once there's real parser coverage for its JSON output.",
        "install_cmd": "docker pull checkmarx/kics",
        "docs_url": "https://docs.kics.io/latest/getting-started/",
        "version_cmd": ["kics", "version"],
    },
]

# Usage-assignment surfaces a tool can be turned on/off for, per workspace
# (issue #75's "per-tool usage assignment"). Kept as a plain tuple rather
# than an Enum so app/api/tools.py's WorkspaceToolConfig payload validation
# and the frontend's toggle list share one literal source without an extra
# import surface -- WorkspaceToolConfig itself declares the four columns
# explicitly (see models.py), this tuple is only for validating which
# field names a PUT may target.
USAGE_SURFACES = ("on_demand_scan", "ci_pipeline", "api_scan", "pr_guardrail")


def default_usage_for(tool: str) -> dict:
    """Built-in usage-surface defaults for a tool with no saved
    WorkspaceToolConfig row (issue #75). Mirrors WorkspaceToolConfig's own
    column defaults for an *integrated* tool (on-demand/CI/PR guardrail on,
    API scan off since #72 isn't wired up yet) but forces every surface off
    for a registry-only tool like kics that has no real TOOL_COMMANDS
    entry -- there is nothing to "run" for it yet, so defaulting it to
    enabled would be a silent no-op that misleads an admin into thinking
    it's active.
    """
    integrated = tool in TOOL_COMMANDS
    return {
        "on_demand_scan": integrated,
        "ci_pipeline": integrated,
        "api_scan": False,
        "pr_guardrail": integrated,
    }


def registry_with_integration_status() -> list[dict]:
    """Registry entries plus a computed `integrated` flag -- True only when
    the tool has a real TOOL_COMMANDS entry (i.e. OSP can actually execute
    a scan for it today), False for registry-only/health-check-only tools
    like kics above."""
    out = []
    for entry in TOOL_REGISTRY:
        out.append({**entry, "integrated": entry["tool"] in TOOL_COMMANDS})
    return out
