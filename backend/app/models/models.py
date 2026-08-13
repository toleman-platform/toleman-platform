from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class FindingState(str, Enum):
    OPEN = "Open"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"
    WONT_FIX = "Won't Fix"
    MITIGATED = "Mitigated"
    REOPENED = "Reopened"


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    DEVELOPER = "developer"
    SECURITY_ENGINEER = "security_engineer"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str
    password_hash: str
    role: UserRole = UserRole.ADMIN
    token_version: int = Field(default=1)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Workspace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id")
    name: str
    api_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class WorkspaceRole(str, Enum):
    """Per-workspace role vocabulary (issue #32). Deliberately a subset of
    the global UserRole values -- 'admin' isn't here because admin-ness is
    global (see WorkspaceMembership docstring), and 'user' isn't here
    because it carries no meaning at the workspace-scoped resource layer
    (targets/findings/PR guardrail/SBOM/discovery); every non-admin who
    needs to act within a workspace needs at least viewer."""
    VIEWER = "viewer"
    DEVELOPER = "developer"
    SECURITY_ENGINEER = "security_engineer"


# Ordering used by app.api.auth.enforce_workspace_role to compare a caller's
# membership role against a route's minimum required role. Mirrors the
# real permission shape already enforced globally by require_security_reviewer
# (admin/security_engineer > everyone else) plus a viewer < developer step.
WORKSPACE_ROLE_RANK = {
    WorkspaceRole.VIEWER: 1,
    WorkspaceRole.DEVELOPER: 2,
    WorkspaceRole.SECURITY_ENGINEER: 3,
}


class WorkspaceMembership(SQLModel, table=True):
    """Per-workspace role assignment (issue #32), layered on top of the
    existing global User.role rather than replacing it: a global admin
    still manages everything everywhere (see enforce_workspace_role), and
    this table is what determines a *non-admin's* permissions within one
    specific workspace. One row per (user, workspace) -- re-assigning a
    user's role for a workspace updates this row rather than adding a
    second one (see app/api/admin_workspace_roles.py)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    role: WorkspaceRole = WorkspaceRole.VIEWER
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Target(SQLModel, table=True):
    """A repository / cluster being scanned."""
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    repo_url: str
    default_branch: str = "main"
    label: str = "Dev"  # Prod, Dev, Internal, Public, or custom
    criticality_weight: int = 1  # 1-5
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Project(SQLModel, table=True):
    """Specific file/image scope within a Target (currently 1:1 with Target for MVP)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    tool: str
    branch: str
    status: str = "running"  # running, completed, failed
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings_count: int = 0


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    project_id: Optional[int] = Field(default=None, foreign_key="project.id")
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id")

    dedup_hash: str = Field(index=True)
    tool: str
    rule_id: str
    title: str
    description: str = ""
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    severity: Severity
    priority_score: int = Field(default=0, index=True)

    branch: str = Field(default="main", index=True)
    state: FindingState = Field(default=FindingState.OPEN, index=True)
    state_reason: str = ""

    cve_id: Optional[str] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False

    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    mitigated_at: Optional[datetime] = None


class PlatformConfig(SQLModel, table=True):
    """Single-row runtime configuration, editable via Admin > Global Integrations."""
    id: Optional[int] = Field(default=None, primary_key=True)
    anthropic_api_key: Optional[str] = None
    # AI Analysis provider selection: "anthropic" (default) or "openai_compatible".
    # The openai_compatible fields cover any self-hosted/OpenAI-compatible chat
    # completions endpoint -- Kimi/Moonshot, Ollama, vLLM, LM Studio, etc.
    ai_provider: str = "anthropic"
    openai_compatible_base_url: str = ""
    # Encrypted at rest via app.core.crypto.encrypt_secret (unlike
    # anthropic_api_key above, which is a pre-existing plaintext field left
    # untouched).
    openai_compatible_api_key: str = ""
    openai_compatible_model: str = ""
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class GitHubAppConfig(SQLModel, table=True):
    """One row per registered GitHub App (multi-install support, #34) -- a
    platform can have several Apps registered (e.g. a dev App and a prod
    App) and each GitHubInstallation records which App it belongs to via
    ``GitHubInstallation.github_app_config_id``, since minting an
    installation token requires signing a JWT with *that* App's private
    key/app_id specifically.

    ``setup_token`` is the CSRF ``state`` value from the manifest flow that
    created this row, reused as a permanent, opaque marker baked into this
    App's ``setup_url`` (see app/core/github_app.py:build_manifest) so every
    future GitHub "install"/"configure" callback for this specific App can
    be routed back to the right config row without guessing. Nullable only
    for rows created before this column existed (pre-#34) -- those are
    resolved via the single-config fallback in
    app/core/github_app.py:resolve_config_for_installation.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    app_id: str
    slug: str
    client_id: str
    client_secret: str
    private_key_pem: str
    webhook_secret: str
    html_url: str
    setup_token: Optional[str] = Field(default=None, unique=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class GitHubInstallation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    installation_id: int = Field(unique=True, index=True)
    account_login: str
    account_type: str
    workspace_id: int = Field(foreign_key="workspace.id")
    # Which App this installation belongs to (#34: a platform may have
    # multiple GitHubAppConfig rows). Nullable for rows created before this
    # column existed; those are only resolvable when exactly one
    # GitHubAppConfig exists (see resolve_config_for_installation).
    github_app_config_id: Optional[int] = Field(default=None, foreign_key="githubappconfig.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingStateLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    from_state: str
    to_state: str
    reason: str = ""
    actor: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class PRGuardrailStatus(str, Enum):
    RUNNING = "running"
    PASSED = "passed"
    BLOCKED = "blocked"
    ERROR = "error"
    OVERRIDDEN = "overridden"


class ApiEndpoint(SQLModel, table=True):
    """A persisted API Discovery result. Previously ephemeral (re-run every
    time, results lost on reload) - now upserted per target+branch so the
    page shows real state without re-scanning, and a discovery run can
    highlight which endpoints are new since the last run (first_seen ==
    this run's timestamp) the same way Finding/dedup already does."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    framework: str
    method: str
    route: str
    file_path: str
    line: int | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class SbomComponent(SQLModel, table=True):
    """A persisted SBOM Generation result (`trivy fs --format cyclonedx`).
    Upserted per target+branch, mirroring ApiEndpoint above, so the page
    shows real state without re-scanning and a generate run can highlight
    which components are new since the last run."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    name: str
    version: str
    package_type: str
    purl: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class PRGuardrailScan(SQLModel, table=True):
    """A PR Guardrail diff-scan run (architecture doc Flow C).

    Net-new findings from this run are NOT persisted as platform Finding rows
    (that would pollute default-branch posture with PR-branch-only noise) --
    but each one IS persisted as a PRGuardrailFinding (below), scoped to this
    scan, so an individual finding can be linked to and have its own
    ignore/approval lifecycle without touching the main Finding table.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    pr_number: int
    pr_title: str = ""
    branch: str  # PR head branch
    status: PRGuardrailStatus = PRGuardrailStatus.RUNNING
    new_findings_count: int = 0
    highest_new_severity: str | None = None  # "Critical"/"High"/etc, or None
    new_endpoints_count: int = 0  # API Discovery: endpoints newly appearing in the PR diff
    override_reason: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None


class IgnoreStatus(str, Enum):
    NONE = "none"
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"


class PRGuardrailFinding(SQLModel, table=True):
    """One net-new finding from a PRGuardrailScan, persisted so it can be
    deep-linked from the GitHub PR comment back into the platform and carry
    its own ignore-request/approval state (developer requests, security
    engineer or admin approves/rejects -- see app/api/pr_guardrail.py)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    pr_scan_id: int = Field(foreign_key="prguardrailscan.id", index=True)
    tool: str
    rule_id: str
    title: str
    file_path: str
    line_start: int | None = None
    severity: str  # "Critical"/"High"/etc -- stored as str, not Severity, since these aren't platform Findings

    ignore_status: IgnoreStatus = IgnoreStatus.NONE
    ignore_requested_by: str = ""
    ignore_requested_reason: str = ""
    ignore_reviewed_by: str = ""
    ignore_reviewed_at: datetime | None = None


class PolicyRuleType(str, Enum):
    """ROADMAP Sprint 4 (Policy-as-code): workspace-configurable rules that
    adjust PR Guardrail's default blocking behavior."""
    BLOCK_SEVERITY = "block_severity"       # block PRs with net-new findings at or above this severity
    SUPPRESS_RULE = "suppress_rule"          # suppress findings matching a specific rule_id (org-level, not per-finding)
    SUPPRESS_LICENSE = "suppress_license"    # suppress specific license findings (e.g. allow MIT even if Trivy flags it)


class PolicyRule(SQLModel, table=True):
    """A single workspace-scoped policy-as-code rule. Soft-deleted (active=False)
    rather than hard-deleted since these are audit-relevant."""
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    rule_type: PolicyRuleType
    value: str  # for BLOCK_SEVERITY: "Critical"/"High"/"Medium"/"Low"; for SUPPRESS_RULE: a rule_id substring/exact match; for SUPPRESS_LICENSE: a license name like "MIT"
    reason: str = ""
    created_by: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = True
