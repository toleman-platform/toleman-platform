from datetime import datetime
from enum import Enum
from typing import Optional
from sqlalchemy import Column, JSON, UniqueConstraint
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
    # PR Guardrail enforcement mode (issue #62): "block" (fail the build on
    # policy-blocking findings), "alert" (still scan + comment, but the
    # commit status is non-blocking), or "disabled" (skip PR Guardrail
    # entirely). None means "no workspace-level override configured" -- NOT
    # "alert" -- see app.core.enforcement.resolve_enforcement_mode for the
    # workspace -> group -> target most-specific-wins resolution and the
    # hardcoded "block" default when nothing is set anywhere.
    enforcement_mode: Optional[str] = None


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
    # Pipeline integration (issue #66): whether a real PR opening
    # .github/workflows/osp-scan.yml against this target's default GitHub
    # repo has been opened via the GitHub App. pipeline_pr_url is the actual
    # PR that was opened (kept even after merge/close, as a record of what
    # happened -- not re-checked live against GitHub's PR state).
    pipeline_integrated: bool = False
    pipeline_pr_url: Optional[str] = None
    # PR Guardrail enforcement mode (issue #62), same "block"/"alert"/
    # "disabled" vocabulary as Workspace.enforcement_mode/Group.enforcement_mode.
    # None means "inherit" (from this target's group(s), then its workspace,
    # then the hardcoded "block" default) -- see app.core.enforcement.
    enforcement_mode: Optional[str] = None


class Group(SQLModel, table=True):
    """A workspace-scoped tag/group for organizing Targets at scale (issue
    #61) -- e.g. "production", "PCI-scope", "internal-tool". Foundation for
    group-level policy (block/alert-mode-per-group, #62) and group-level SLA
    (#70) in later sprints; this issue only covers creating/assigning groups
    and filtering by them.

    __tablename__ is set explicitly to "groups" rather than the SQLModel
    default ("group") since GROUP is a reserved SQL keyword -- avoids relying
    on every driver/tool correctly auto-quoting it.
    """
    __tablename__ = "groups"

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    name: str
    color: str = "#6366f1"  # hex color for UI badges
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # PR Guardrail enforcement mode (issue #62), same vocabulary/inheritance
    # role as Target.enforcement_mode/Workspace.enforcement_mode -- None
    # means "no group-level override configured". See app.core.enforcement.
    enforcement_mode: Optional[str] = None


class TargetGroup(SQLModel, table=True):
    """Many-to-many join between Target and Group (issue #61). A target can
    carry multiple groups and a group can contain multiple targets. Kept as
    a plain join table + explicit queries rather than a SQLModel
    Relationship, matching this codebase's existing style (see
    WorkspaceMembership). The unique constraint keeps assigning the same
    group to the same target twice a no-op at the DB level, backing up the
    idempotent-POST handling in app/api/groups.py."""
    __tablename__ = "target_group"
    __table_args__ = (UniqueConstraint("target_id", "group_id", name="uq_target_group_target_id_group_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    group_id: int = Field(foreign_key="groups.id", index=True)
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
    # SLA-breach notification dedup (issue #73): set the first time this
    # finding is observed to be sla_violated at a query-time check (see
    # app.api.findings._maybe_notify_sla_breach), so the same violation
    # doesn't re-fire a Slack message on every subsequent GET. Reset to None
    # if the finding is later mitigated/reopened past its SLA again would be
    # a fresh breach -- see _maybe_notify_sla_breach for the reset rule.
    sla_breach_notified_at: Optional[datetime] = None


class CveEnrichment(SQLModel, table=True):
    """Locally-cached, AI-free enrichment for a single CVE ID (issue #71),
    sourced from NVD (description/CVSS/CWE) and OSV.dev (known fixed
    versions) -- explicitly *not* the AI Analysis feature (`app/api/ai.py`),
    so this must work with zero AI provider configured.

    NVD/OSV data for a given published CVE is effectively immutable, unlike
    KEV's whole-catalog daily refresh (`core/kev.py`) or EPSS's score that
    genuinely changes over time -- a real DB row cached "forever" (fetched
    once, never re-fetched) is the right shape here, not the in-process TTL
    cache pattern used for KEV/EPSS batch lookups.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(unique=True, index=True)

    # NVD (https://nvd.nist.gov/developers/vulnerabilities)
    nvd_description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: Optional[str] = None  # JSON-encoded list[str], e.g. '["CWE-444"]'
    nvd_references: Optional[str] = None  # JSON-encoded list[str] of URLs
    nvd_found: bool = Field(default=False)

    # OSV.dev (https://osv.dev/docs) -- queried directly by CVE ID via
    # GET /v1/vulns/{cve_id}, which resolves CVE as an alias without needing
    # package/ecosystem context.
    osv_id: Optional[str] = None
    fixed_versions: Optional[str] = None  # JSON-encoded list[dict] (package/ecosystem/fixed)
    osv_references: Optional[str] = None  # JSON-encoded list[str] of URLs
    osv_found: bool = Field(default=False)

    fetched_at: datetime = Field(default_factory=datetime.utcnow)


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
    # Slack incoming-webhook config (issue #74): a single webhook URL used
    # both for the "Test Connection" button and (future work) alert
    # notifications. Encrypted at rest via app.core.crypto.encrypt_secret,
    # same pattern as openai_compatible_api_key above -- a webhook URL is a
    # bearer credential (anyone with it can post to the channel).
    slack_webhook_url: str = ""
    # Jira API config (issue #74): server URL (e.g.
    # "https://yourorg.atlassian.net"), an API token (encrypted, same pattern
    # as the webhook URL/openai key above), the project key issues get
    # created under (e.g. "SEC"), and the issue type name (e.g. "Bug",
    # "Task") -- both project key and issue type are plain strings, not
    # validated against the live Jira instance's schema (that would require a
    # real authenticated call on every save; "Test Connection" is the
    # explicit real-call verification step instead).
    jira_url: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    jira_issue_type: str = "Task"
    # Auto-ticket-creation criteria (issue #74 v1): a single severity
    # threshold, e.g. "Critical" auto-creates a Jira ticket for every new
    # Critical finding at ingestion time (see app.core.ingestion /
    # app.core.jira_integration). None/"" means disabled. Deliberately a
    # single scalar rather than a rule table for this first version -- see
    # PolicyRule/SlaRule for the shape a future multi-rule version could grow
    # into if needed.
    jira_auto_create_severity: Optional[str] = None
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


class DiscoveryRun(SQLModel, table=True):
    """Tracks a single async API Discovery run dispatched via Celery (#59).

    POST /api/discovery/{target_id} used to clone+grep synchronously inside
    the request handler; a handful of concurrent requests could exhaust
    FastAPI's threadpool. Now the endpoint creates this row, dispatches
    app.tasks.discovery_tasks.run_discovery via .delay(), and returns
    immediately with this row's id -- the frontend polls
    GET /api/discovery/{target_id}/runs/{run_id} until status leaves
    "running", the same running/completed/failed lifecycle Scan already
    uses for native scans."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    status: str = "running"  # running, completed, failed
    error: str = ""
    count: int = 0
    new_count: int = 0
    # Comma-separated ApiEndpoint ids that were net-new on this specific run
    # -- lets GET .../runs/{run_id} report accurate per-endpoint is_new flags
    # (mirroring what the old synchronous POST response used to compute
    # inline) without guessing from timestamps after the fact.
    new_ids: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


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


class SbomRun(SQLModel, table=True):
    """Tracks a single async SBOM generation run dispatched via Celery
    (#59) -- same running/completed/failed lifecycle as DiscoveryRun above,
    for POST /api/sbom/{target_id}."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    status: str = "running"  # running, completed, failed
    error: str = ""
    count: int = 0
    new_count: int = 0
    # Comma-separated SbomComponent ids that were net-new on this run --
    # same rationale as DiscoveryRun.new_ids above.
    new_ids: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


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


class PipelineIntegrationBatch(SQLModel, table=True):
    """Tracks a single async bulk "Add Pipeline" run dispatched via Celery
    (issue #68, the multi-select wrapper around #66's single-target
    pipeline-integration mechanism). Mirrors the DiscoveryRun/SbomRun
    async-job-tracking pattern from #59: POST
    /api/targets/bulk-pipeline-integrate creates this row (status="running"),
    dispatches app.tasks.pipeline_tasks.run_pipeline_integration_batch via
    .delay(), and returns immediately with this row's id -- the frontend
    polls GET /api/targets/pipeline-integration-batches/{batch_id} until
    status leaves "running". No workspace_id here: a caller (e.g. a global
    admin) may select targets spanning several workspaces in one batch, so
    per-target access is checked per target at dispatch time (POST handler)
    instead of once at the batch level.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    created_by_user_id: int = Field(foreign_key="user.id")
    status: str = "running"  # running, completed
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    already_integrated: int = 0
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class PipelineIntegrationBatchItem(SQLModel, table=True):
    """One target's outcome within a PipelineIntegrationBatch (#68). Each
    item involves a real GitHub API call (branch create + content write +
    PR open, via #66's open_pipeline_pr) -- the Celery task processes items
    sequentially with a small delay between them rather than firing them
    all concurrently, to stay polite to GitHub's rate limits."""
    id: Optional[int] = Field(default=None, primary_key=True)
    batch_id: int = Field(foreign_key="pipelineintegrationbatch.id", index=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    status: str = "pending"  # pending, running, succeeded, failed, already_integrated
    error: str = ""
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    completed_at: Optional[datetime] = None


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


class SlaRule(SQLModel, table=True):
    """A workspace-scoped SLA (days-to-fix) rule, keyed by severity and
    optionally a repo Group (issue #70) -- e.g. "Critical findings in the
    'production' group must be fixed within 7 days", or a workspace-wide
    default of "Medium findings get 30 days" for targets with no
    group-specific rule.

    Unlike #62's enforcement_mode (a single inherited scalar per level),
    an SLA is naturally a matrix of (group-or-workspace-default, severity)
    -> days_to_fix, since "Critical" and "Low" need very different windows
    even within the same group. group_id is nullable: NULL means
    "workspace-default", applied to a target only when none of its groups
    carry a rule for that severity -- see
    app.core.sla.resolve_sla_days for the group -> workspace-default -> "no
    SLA" resolution (deliberately not the enforcement.py 3-level target ->
    group -> workspace chain, since there's no per-target SLA override in
    this first version; targets inherit purely through their group(s)).

    The (workspace_id, group_id, severity) unique constraint is the intended
    shape of "at most one rule per group+severity, and at most one workspace
    default per severity" -- note Postgres treats NULL as distinct for
    uniqueness purposes, so this constraint alone doesn't stop two NULL-
    group_id rows for the same (workspace_id, severity); the API layer
    (app/api/sla_rules.py) additionally checks for an existing match before
    insert so duplicate workspace-default rules are rejected with a 409
    rather than silently multiplying.
    """
    __table_args__ = (
        UniqueConstraint("workspace_id", "group_id", "severity", name="uq_sla_rule_workspace_group_severity"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    group_id: Optional[int] = Field(default=None, foreign_key="groups.id", index=True)
    severity: Severity
    days_to_fix: int
    created_at: datetime = Field(default_factory=datetime.utcnow)


class WorkspaceToolConfig(SQLModel, table=True):
    """Per-workspace, per-tool usage assignment (issue #75): which of the
    tool registry's four usage surfaces (`app.core.tool_registry.
    USAGE_SURFACES`) a given scanner is enabled for in this workspace --
    on-demand ("Scan now" from the Targets page), CI pipeline (the
    generated GitHub Actions workflow from #66/pipeline_workflow.py),
    active API scanning (#72, not yet wired to actually read this flag --
    the column exists now so the assignment UI has one stable place to
    grow into once #72 ships), and PR Guardrail diff scans.

    Absence of a row for a (workspace_id, tool) pair means "use the
    built-in default", not "disabled" -- see
    `app.core.tool_registry.default_usage_for` for the defaults (mirrors
    the "None = inherit" philosophy already used by Workspace/Group/Target
    .enforcement_mode in #62, rather than requiring every workspace to
    explicitly configure every tool before any of them run).
    """
    __table_args__ = (
        UniqueConstraint("workspace_id", "tool", name="uq_workspace_tool_config_workspace_tool"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    tool: str = Field(index=True)
    on_demand_scan: bool = True
    ci_pipeline: bool = True
    api_scan: bool = False
    pr_guardrail: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class NotificationChannel(str, Enum):
    """Delivery channel for a NotificationPreference (issue #73). `slack`
    posts to the single platform-wide webhook configured in
    PlatformConfig.slack_webhook_url (#74) -- there's no per-user Slack
    OAuth/DM capability in this project, so a user "enabling Slack" means
    "mention me in the message posted to the platform's configured Slack
    channel", not a private DM. `email` has a preference row so a user's
    intent is recorded, but there is deliberately no real SMTP/email-sending
    infrastructure anywhere in this codebase yet -- see
    app.core.notifications.dispatch_notification, which no-ops (with a clear
    log line) for this channel rather than fabricating a delivery."""
    EMAIL = "email"
    SLACK = "slack"


class NotificationEventType(str, Enum):
    """What can trigger a notification (issue #73). See
    app.core.notifications for where each of these actually fires:
    critical_finding/kev_cve at ingestion time (app.core.ingestion, same
    hook point as #74's Jira auto-create), sla_breach at the query-time
    point #70 already computes SLA violation (app.api.findings), and
    scan_failure when a Scan/DiscoveryRun/SbomRun transitions to status
    "failed" (app.tasks.*)."""
    CRITICAL_FINDING = "critical_finding"
    KEV_CVE = "kev_cve"
    SLA_BREACH = "sla_breach"
    SCAN_FAILURE = "scan_failure"


class NotificationPreference(SQLModel, table=True):
    """One user's opt-in for one (channel, event_type) pair (issue #73).
    Absence of a row means "not enabled" -- there's no default-on behavior,
    matching this project's "never fabricate a default a user didn't set"
    philosophy (see SlaRule/enforcement_mode docstrings). The unique
    constraint keeps PUT /api/notification-preferences an idempotent
    upsert rather than accumulating duplicate rows on repeated saves."""
    __table_args__ = (
        UniqueConstraint(
            "user_id", "channel", "event_type", name="uq_notification_pref_user_channel_event"
        ),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    channel: NotificationChannel
    event_type: NotificationEventType
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DashboardLayout(SQLModel, table=True):
    """A user's configurable dashboard composition (issue #69), replacing
    the previous single fixed layout in frontend/(dashboard)/page.tsx.

    `widgets` is an ordered JSON list of widget *instances*:
    ``[{"id": "<uuid>", "widget_id": "kpi_cards", "config": {...}}, ...]``.
    `id` is a per-instance identifier (stable across reorders/renames so the
    frontend can key React lists and target a specific instance for
    remove/move, distinct from `widget_id` which names the concrete widget
    *type* in app.core.widgets.WIDGET_CATALOG). `config` is deliberately
    minimal -- a widget's own scope filter (e.g. `{"limit": 10}` for recent
    findings), not a generic arbitrary-chart-config blob; see
    app.core.widgets for the concrete (non-generic) widget catalog this
    project chose instead of a build-your-own-chart system.

    One row per user (unique user_id) -- absence of a row means "no custom
    layout saved yet", resolved by GET /api/dashboard/layout to
    app.core.widgets.build_default_layout()'s sensible default set rather
    than an empty dashboard.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", unique=True, index=True)
    widgets: list = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow)
