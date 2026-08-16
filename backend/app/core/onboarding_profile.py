"""First-run questionnaire (issue #203): turning "what kind of shop is this?"
into tooling defaults.

A fresh deployment previously enabled every scanner regardless of what the
operator actually runs -- gosec on an estate with no Go, Checkov on one with
no Terraform, the AI ruleset on a shop that ships no models. The platform
already knows how to run all of them; nothing asked which were relevant.

THE RULE THIS MODULE IS BUILT AROUND: answers only ever *narrow* what runs,
and never silently. A tool switched off by an answer is recorded with the
reason, surfaced as disabled-with-reason in the marketplace, and re-enabled
in one click. Silently reducing scanner coverage on a security tool is the
worst failure available here -- it is the same "absence of evidence is not
evidence of absence" line that runs through #174, #186 and #190. An operator
must never discover months later that Rikugan quietly stopped looking for
something because of a checkbox they ticked on day one.

Answers are advisory input to WorkspaceToolConfig (#75), which stays the
single source of truth for what is enabled. This module maps one to the
other; it does not invent a second switch.
"""
from dataclasses import dataclass

# Answer vocabularies. Slugs are stored; labels are the UI's business.
LANGUAGE_CHOICES = [
    ("python", "Python"),
    ("javascript", "JavaScript / TypeScript"),
    ("go", "Go"),
    ("java", "Java / Kotlin"),
    ("ruby", "Ruby"),
    ("php", "PHP"),
    ("csharp", "C# / .NET"),
    ("rust", "Rust"),
    ("other", "Something else"),
]

CLOUD_CHOICES = [
    ("aws", "AWS"),
    ("gcp", "Google Cloud"),
    ("azure", "Azure"),
    ("onprem", "On-premise / self-hosted"),
    ("none", "None yet"),
]

PR_ENFORCEMENT_CHOICES = [
    ("block", "Block the merge on new findings"),
    ("alert", "Comment only, never block"),
]


@dataclass
class ToolRecommendation:
    """One tool's suggested state, plus why. `reason` is not decoration --
    it is what makes a disabled tool contestable instead of mysterious."""

    tool: str
    enabled: bool
    reason: str


def parse_csv(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def recommend_tools(
    languages: list[str],
    uses_iac: bool | None,
    builds_ai_features: bool | None,
    ships_containers: bool | None,
) -> list[ToolRecommendation]:
    """Suggested tool enablement for the answers given.

    Only tools with a *positive reason to be off* are ever recommended off.
    An unanswered question (None) leaves the tool on: "not stated" is not
    "no", and the safe default for a security scanner is to run.
    """
    recs: list[ToolRecommendation] = []

    # Always-on, language-agnostic. Listed explicitly so the wizard can show
    # the operator the full picture rather than only what it turned off.
    for tool, why in [
        ("semgrep", "Covers most mainstream languages; useful on every repo."),
        ("gitleaks", "Secret detection is language-agnostic and always worth running."),
        ("trivy", "Dependency vulnerabilities apply to every ecosystem."),
        ("trivy-license", "License compliance applies to every ecosystem."),
    ]:
        recs.append(ToolRecommendation(tool=tool, enabled=True, reason=why))

    # gosec is Go-only. Off only when languages were actually stated and Go
    # was not among them -- an empty answer leaves it on.
    if languages and "go" not in languages:
        recs.append(
            ToolRecommendation(
                tool="gosec",
                enabled=False,
                reason="Go-specific, and Go was not listed among your languages. Re-enable any time.",
            )
        )
    else:
        recs.append(ToolRecommendation(tool="gosec", enabled=True, reason="Go static analysis."))

    for tool, label in [("checkov", "Checkov"), ("tfsec", "tfsec")]:
        if uses_iac is False:
            recs.append(
                ToolRecommendation(
                    tool=tool,
                    enabled=False,
                    reason=f"{label} scans infrastructure-as-code, which you said you do not use.",
                )
            )
        else:
            recs.append(
                ToolRecommendation(
                    tool=tool,
                    enabled=True,
                    reason="Infrastructure-as-code misconfiguration scanning.",
                )
            )

    # AI tooling. Note these are *additionally* gated per repo by #185's
    # detection at scan time, so a "no" here is a default, never an override
    # of what the platform actually finds in a repository.
    for tool, label in [("modelscan", "ModelScan"), ("semgrep-llm", "the LLM ruleset")]:
        if builds_ai_features is False:
            recs.append(
                ToolRecommendation(
                    tool=tool,
                    enabled=False,
                    reason=(
                        f"You said you do not build AI/ML features, so {label} is off by default. "
                        "Repositories are still checked for AI/ML content on every scan, and this "
                        "can be switched back on at any time."
                    ),
                )
            )
        else:
            recs.append(
                ToolRecommendation(
                    tool=tool,
                    enabled=True,
                    reason="Runs only on repositories detected as AI/ML.",
                )
            )

    return recs


def recommendation_summary(recs: list[ToolRecommendation]) -> dict:
    disabled = [r for r in recs if not r.enabled]
    return {
        "enabled": len(recs) - len(disabled),
        "disabled": len(disabled),
        "disabled_tools": [{"tool": r.tool, "reason": r.reason} for r in disabled],
    }
