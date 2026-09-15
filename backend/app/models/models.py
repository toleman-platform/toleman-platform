from datetime import datetime
from enum import Enum
from typing import Optional
from sqlalchemy import Column, Index, JSON, UniqueConstraint, text
from sqlmodel import SQLModel, Field

from app.core.time import utcnow


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


# "Still needs attention" vs "already triaged/resolved" -- the split
# app.core.security_score/app.core.widgets already use for posture
# calculations (open-findings counts, SLA compliance, etc), and now also
# the Findings page's own Open/Resolved split (app/api/findings.py). Kept
# here, next to FindingState itself, as the one definition every caller
# imports rather than three independent hardcoded tuples drifting apart.
OPEN_FINDING_STATES = (FindingState.OPEN, FindingState.REOPENED)
RESOLVED_FINDING_STATES = (
    FindingState.ACCEPTED_RISK,
    FindingState.FALSE_POSITIVE,
    FindingState.WONT_FIX,
    FindingState.MITIGATED,
)


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
    created_at: datetime = Field(default_factory=utcnow)


class AuthEventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"
    ROLE_CHANGED = "role_changed"
    WORKSPACE_ROLE_CHANGED = "workspace_role_changed"
    WORKSPACE_ROLE_REMOVED = "workspace_role_removed"
    # (#273) Target lifecycle. These aren't access-control events like the
    # six above, but they belong in the same trail for the same reason:
    # they're the destructive platform actions whose *absence* from a log
    # would be the problem. "Who stopped scanning this repo, and when" and
    # "who deleted the record of these findings" are exactly the questions a
    # security tool has to be able to answer about itself, and AuthAuditLog
    # is this codebase's only real audit *write* path (log_auth_event); the
    # findings feed in app/api/audit.py is derived from FindingStateLog/Scan
    # rows rather than written to directly, so there is nothing there to
    # record "a target stopped existing" against.
    TARGET_DEACTIVATED = "target_deactivated"
    TARGET_REACTIVATED = "target_reactivated"
    TARGET_DELETED = "target_deleted"


class AuthAuditLog(SQLModel, table=True):
    """Security-relevant account activity: who logged in/out, when, from
    where, and who changed whose permissions. Deliberately separate from
    FindingStateLog/Scan (what `GET /api/audit/log` already renders as the
    Audit Log page) -- that feed is "what happened to our vulnerability
    posture" and is visible to any authenticated user; this one is "who did
    what to this platform's own access control" and is admin-only
    (`GET /api/audit/security-log`, gated the same way app/api/admin.py's
    user management already is), a different sensitivity level entirely.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    event_type: AuthEventType = Field(index=True)
    # Who performed the action. For LOGIN_SUCCESS/LOGIN_FAILED/LOGOUT/
    # PASSWORD_CHANGED this is the same person the event is about; for
    # ROLE_CHANGED/WORKSPACE_ROLE_CHANGED/WORKSPACE_ROLE_REMOVED this is the
    # admin who made the change, which can differ from target_email below.
    actor: str = Field(index=True)
    # The user the event is about. Defaults to `actor` at write time for the
    # self-service events (login/logout/password) so every row is
    # filterable by "events about user X" regardless of event type, without
    # a nullable column meaning two different things.
    target_email: str = ""
    detail: str = ""
    # Best-effort (Request.client can be None behind some proxies/test
    # clients); never blocks logging the event itself.
    ip_address: str = ""
    created_at: datetime = Field(default_factory=utcnow, index=True)


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utcnow)


class Workspace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id")
    name: str
    api_key: str
    created_at: datetime = Field(default_factory=utcnow)
    # PR Guardrail enforcement mode (issue #62): "block" (fail the build on
    # policy-blocking findings), "alert" (still scan + comment, but the
    # commit status is non-blocking), or "disabled" (skip PR Guardrail
    # entirely). None means "no workspace-level override configured" (NOT
    # "alert") see app.core.enforcement.resolve_enforcement_mode for the
    # workspace -> group -> target most-specific-wins resolution and the
    # hardcoded "block" default when nothing is set anywhere.
    enforcement_mode: Optional[str] = None


class WorkspaceRole(str, Enum):
    """Per-workspace role vocabulary (issue #32). Deliberately a subset of
    the global UserRole values; 'admin' isn't here because admin-ness is
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
    specific workspace. One row per (user, workspace); re-assigning a
    user's role for a workspace updates this row rather than adding a
    second one (see app/api/admin_workspace_roles.py)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    role: WorkspaceRole = WorkspaceRole.VIEWER
    created_at: datetime = Field(default_factory=utcnow)


class Target(SQLModel, table=True):
    """A repository / cluster being scanned."""
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    repo_url: str
    default_branch: str = "main"
    label: str = "Dev"  # Prod, Dev, Internal, Public, or custom
    criticality_weight: int = 1  # 1-5
    # (#251) Who owns this and where it runs.
    #
    # criticality_weight already multiplies every finding's priority_score
    # (app/core/scoring.py), but nothing recorded *why* a target is critical,
    # so the number was an assertion nobody could audit or argue with. These
    # three make it explainable, and give findings the facets people actually
    # filter by; "show me production only", "route this to its owner"
    # instead of to everyone.
    #
    # Deliberately free-text/nullable rather than enums-with-a-migration:
    # every org names its environments differently (prod/production/live), and
    # guessing that vocabulary would force a rename on anyone who disagreed.
    # None means "not recorded", which stays distinct from any real value.
    owner: Optional[str] = None          # team or person accountable
    environment: Optional[str] = None    # production / staging / dev / ...
    lifecycle: Optional[str] = None      # active / maintenance / deprecated / ...
    created_at: datetime = Field(default_factory=utcnow)
    # Pipeline integration (issue #66): whether a real PR opening
    # .github/workflows/toleman-scan.yml against this target's default GitHub
    # repo has been opened via the GitHub App. pipeline_pr_url is the actual
    # PR that was opened (kept even after merge/close, as a record of what
    # happened; not re-checked live against GitHub's PR state).
    pipeline_integrated: bool = False
    pipeline_pr_url: Optional[str] = None
    # PR Guardrail enforcement mode (issue #62), same "block"/"alert"/
    # "disabled" vocabulary as Workspace.enforcement_mode/Group.enforcement_mode.
    # None means "inherit" (from this target's group(s), then its workspace,
    # then the hardcoded "block" default); see app.core.enforcement.
    enforcement_mode: Optional[str] = None
    # (#243) Scan only the PR's changed files instead of the whole checkout.
    # Defaults False: this trades coverage for speed (a change in file A
    # can make pre-existing code in file B vulnerable, and a diff-scoped scan
    # will not see it) so it must be switched on deliberately per target
    # rather than silently narrowing what everyone's PR gate checks.
    diff_scoped_pr_scans: bool = False
    # Issue #72 (Active API Scanning): the live base URL of this target's
    # deployed API, e.g. "https://api-staging.example.com". Deliberately a
    # user-set, per-target field rather than anything derived from repo_url
    # (a git clone URL, not a runtime host); active scanning combines this
    # with routes already persisted in ApiEndpoint (Sprint 1's static
    # discovery) to build the exact URL list nuclei is invoked against. None
    # means active scanning is not configured for this target yet; the scan
    # trigger endpoint refuses to run rather than guessing a host. This is
    # the ONLY source of a scan target host (never taken from request
    # input) so a caller can never point an active scan at an arbitrary
    # third-party URL, only at a host this target's owner explicitly
    # declared as belonging to it.
    api_base_url: Optional[str] = None

    # (#470) Credential the active API scanner presents, so it tests the API
    # rather than the login wall. Without it every probe is anonymous, every
    # authenticated route answers 401, and the scan still reports success --
    # an all-clear that is evidence of nothing.
    #
    # Modelled as one arbitrary header rather than a typed "auth method"
    # because that single shape already covers bearer tokens, API keys and
    # most service-to-service auth, and a wrong guess at an enum of methods
    # is harder to undo than adding a second field later. The NAME is not
    # secret and is stored in the clear so the UI can show what is
    # configured; the VALUE is encrypted at rest with the same
    # core.crypto.encrypt_secret used for the GitHub App private key, and is
    # never returned by any route, logged, or included in a scan's stored
    # invocation.
    api_auth_header_name: Optional[str] = None
    api_auth_header_value_ciphertext: Optional[str] = None

    # (#330) Outcome of the automatic GitHub Dependency Graph import that
    # runs when a target is created or imported. Persisted per target so
    # the result survives a reload; a task-result lookup would not.
    #
    # None means "never attempted" (targets that predate this, or whose
    # repo_url is not a github.com repo), which stays distinct from
    # "unavailable". "unavailable" is GitHub declining to answer (graph off,
    # private repo with no token, 403/404); it is NOT an empty inventory,
    # and must never render as clean. "ok" with a count of 0 is the only
    # thing that means "GitHub says this repo has no dependencies".
    # "skipped" (#273) is the import declining to run because the target is
    # deactivated: not a failure, and distinct from "unavailable" (GitHub
    # refused to answer) -- nothing here needs fixing, the inventory is just
    # frozen at whatever was last imported.
    dependency_sync_status: Optional[str] = None   # pending / ok / unavailable / failed / skipped
    dependency_sync_error: Optional[str] = None
    dependency_sync_at: Optional[datetime] = None
    dependency_component_count: Optional[int] = None

    # OSV malicious-package check status: a clean result used to render as
    # a bare 0, indistinguishable from a target nobody had ever checked.
    # These three make a clean result a claim with evidence behind it.
    # Separate from dependency_sync_* above because they track a different
    # thing: dependency_sync_* records the GitHub Dependency Graph import;
    # this records the OSV check itself, which runs from three places that
    # don't touch dependency_sync_* at all: a plain re-check over whatever's
    # already persisted (POST .../malware-check), an uploaded external SBOM
    # (POST .../upload), and the best-effort pass inside automatic SBOM
    # generation (app.tasks.sbom_tasks) -- only .../github-sync happens to
    # also touch dependency_sync_*, because it imports *and* checks in one
    # request.
    #
    # All three are written together, and only by a check that actually
    # completed (app.core.osv_malware_ingestion.check_and_ingest_malware).
    # A failed attempt (OSV unreachable) deliberately leaves them untouched
    # rather than stamping "failed" over a real prior result: the honest
    # signal for "we have not managed to verify this recently" is that the
    # timestamp stops advancing, not a fourth status value that would pair
    # a fresh "attempted just now" clock against a stale package count and
    # invite reading the two together as one coherent, current answer.
    #
    # None on all three means "never completed a check" -- every target
    # that predates this, or whose SBOM inventory has always been empty --
    # and must render as an unmeasured unknown, never as a clean 0.
    malware_last_checked_at: Optional[datetime] = None
    malware_last_check_status: Optional[str] = None  # clean / found
    malware_packages_checked: Optional[int] = None

    # AI/ML repo detection (issue #185), the gate every AI-specific
    # scanner in epic #192 runs behind. Recomputed on each scan by
    # app.core.ai_repo_detection, so a repo becomes an AI repo the day
    # someone adds `openai` to package.json, with no human action.
    #
    # `is_ai_repo_signals` records *why* it fired ("AI/ML dependencies:
    # torch, transformers"). A bare boolean isn't contestable; a user who
    # thinks the platform is wrong needs to see what it matched on.
    is_ai_repo: bool = False
    is_ai_repo_signals: str = ""
    # Explicit override, in either direction, and it wins over detection.
    # None = follow detection (the default). True/False = a human decided.
    # Kept separate from `is_ai_repo` rather than just writing the override
    # into it, so detection can keep updating underneath without clobbering
    # the human's decision; and so "auto-detected as AI" and "someone
    # forced this on" stay distinguishable in the UI.
    is_ai_repo_override: Optional[bool] = None

    # (#298) VPN/client-cert-gated clone hosts. repo_url can point at any
    # host an operator has added to EXTRA_CLONE_HOSTS (app/core/config.py),
    # e.g. an internal GitHub Enterprise Server or GitLab instance reachable
    # only over a VPN or requiring mTLS. These three make that reachable:
    # client_cert/key are the mTLS client certificate git presents (mirrors
    # GitHubToken.token_ciphertext - encrypted at rest via
    # app.core.crypto.encrypt_secret/decrypt_secret since they're
    # replayable credentials, never hashed, never echoed back by the API),
    # clone_proxy_url is the HTTP(S) proxy (e.g. a VPN gateway) git's clone
    # should tunnel through. All optional/blank: a target on a normal
    # public github.com repo needs none of this.
    client_cert_ciphertext: str = ""
    client_key_ciphertext: str = ""
    clone_proxy_url: str = ""

    # (#273) Lifecycle. Until this, a registered target was permanent: a
    # decommissioned repo, a typo'd registration and a test target created
    # while exploring the product all accumulated forever, and there was no
    # delete endpoint at all (only DELETE /{id}/groups/{group_id}, which
    # un-tags a target rather than removing it).
    #
    # Two *timestamps* rather than an is_active/is_deleted boolean pair
    # beside them: a boolean plus a "when" column is two fields encoding one
    # fact, and they drift the first time one write path forgets the other.
    # NULL means "not in that state", and the column simultaneously answers
    # when it entered it, which is what the audit trail actually needs.
    # Callers should read these through app.core.target_lifecycle rather
    # than testing the columns ad hoc -- there are a dozen scan-dispatch
    # paths and roughly as many list/aggregate queries that have to agree
    # on the same two predicates.
    #
    # deactivated_at: scanning stops (on-demand, CI push, PR guardrail,
    # active API scan, scheduled baseline refresh, pipeline rollout), but
    # the target stays visible, filterable and fully readable, and its
    # findings keep counting. Reversible.
    deactivated_at: Optional[datetime] = None
    # deleted_at: soft delete. The target disappears from every list, every
    # dashboard/score/report aggregate and every scan dispatch path, but no
    # row is destroyed -- not the Target, not its Findings, Scans or
    # PRGuardrailScans. This is a security tool: "someone deleted the record
    # of a finding" is itself a fact that has to remain answerable, so the
    # default cannot be a cascade that makes the question unanswerable. A
    # hard delete stays available as a deliberate follow-up product call;
    # it is not the thing a Delete button should do by default.
    deleted_at: Optional[datetime] = None


class Group(SQLModel, table=True):
    """A workspace-scoped tag/group for organizing Targets at scale (issue
    #61), e.g. "production", "PCI-scope", "internal-tool". Foundation for
    group-level policy (block/alert-mode-per-group, #62) and group-level SLA
    (#70) in later sprints; this issue only covers creating/assigning groups
    and filtering by them.

    __tablename__ is set explicitly to "groups" rather than the SQLModel
    default ("group") since GROUP is a reserved SQL keyword, avoids relying
    on every driver/tool correctly auto-quoting it.
    """
    __tablename__ = "groups"

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    name: str
    color: str = "#6366f1"  # hex color for UI badges
    created_at: datetime = Field(default_factory=utcnow)
    # PR Guardrail enforcement mode (issue #62), same vocabulary/inheritance
    # role as Target.enforcement_mode/Workspace.enforcement_mode; None
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
    created_at: datetime = Field(default_factory=utcnow)


class Project(SQLModel, table=True):
    """Specific file/image scope within a Target (currently 1:1 with Target for MVP)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    name: str
    created_at: datetime = Field(default_factory=utcnow)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    tool: str
    branch: str
    status: str = "running"  # running, completed, failed
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    # (#153) human-readable failure reason, clone/tool errors and stale-job
    # timeouts (app/core/staleness.py) both write here so GET /api/scans/{id}
    # can surface *why* a scan failed instead of leaving the frontend with
    # only a bare "failed" status.
    error: str = ""
    # (#229) Whether this run could be trusted to have checked what it
    # claims: "healthy", "suspect", or "unknown". Orthogonal to `status`,
    # which only says whether the run finished -- a scan can complete, exit
    # 0 and emit valid JSON while having read a half-written vulnerability
    # database, which is exactly how a repo with five live CVEs came back
    # clean and had all five auto-mitigated.
    #
    # "unknown" is the default because it is the truth for every row written
    # before this existed and for every ingestion path that offers no
    # evidence (the CI/CD push endpoint). It is deliberately not folded into
    # either of the others: "healthy" would assert a check nobody made, and
    # "suspect" would put a warning on a year of legitimate history until
    # users stopped reading warnings.
    health: str = "unknown"
    # Why, in a sentence a user can act on, when health is not "healthy" --
    # including what was done about it (existing findings left open rather
    # than mitigated). Empty otherwise.
    health_note: str = ""


class SnippetScanRun(SQLModel, table=True):
    """An ephemeral pre-commit vulnerability check (issue #108 follow-up to
    the Toleman MCP server): scans a code snippet an MCP client (e.g.
    Claude Code, mid-edit) hands over directly, so a vulnerability can be
    caught *while it's being written*, not just after it lands in the
    Findings inventory via a real scan. Deliberately NOT a Target/Scan/
    Finding: this content was never associated with any repo Toleman
    actually scans, so persisting it as real Findings would misrepresent
    the platform's own posture data (dashboards, security score) with rows
    for code that may never even be committed.

    `content` itself is never stored on this row, only `filename` (for the
    poll response to echo back what was scanned) -- the raw snippet is
    passed straight through to the Celery task as an argument and only
    ever touches disk inside a temp dir the task removes when done, same
    "don't persist what doesn't need to persist" instinct as ApiToken only
    storing a hash of the plaintext token.

    Async (same create-row-then-`.delay()` shape as Scan/DiscoveryRun/
    ToolInstallRun): semgrep's `--config=auto` can hit the network on a
    cold rule cache, too slow/unpredictable to run inside a request
    handler (see app.scanners.runner's own module docstring on why every
    real scanner invocation in this codebase already goes through Celery,
    never synchronously in a request handler)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    filename: str
    status: str = "running"  # running, completed, failed
    findings_json: str = "[]"
    error: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None


class McpAuditLog(SQLModel, table=True):
    """One call to app.api.public_api (issue #108 follow-up) -- every
    endpoint there is reachable by an ApiToken, and the Toleman MCP server
    is the intended, primary caller, so this doubles as "MCP audit log"
    without needing a separate table per API-token integration. Written by
    app.core.mcp_audit.log_mcp_action, one call site per public_api.py
    endpoint (same "single write-path function, many explicit call sites"
    convention as app.core.auth_audit.log_auth_event).

    `user_id` is the token's owner (current_api_token_user already
    resolves this on every call, so it costs nothing extra to capture).
    `agent` is best-effort caller *software* identity, not a person: for
    the streamable-http transport (Toleman's own deployed MCP server) it's
    the MCP client's own User-Agent header, forwarded by mcp-server as
    X-MCP-Agent since stateless_http mode never runs a real MCP
    initialize handshake per HTTP request (so ctx.session.client_params is
    always None there -- see server.py's _resolve_agent for the full
    reasoning); for stdio mode it's the real MCP clientInfo name/version,
    since stdio *does* do one real handshake per process lifetime. Falls
    back to "unknown" for a bare API-token script that isn't the MCP
    server at all (no X-MCP-Agent header sent).

    `target_id`/`finding_id` are nullable -- not every action is scoped to
    one (list_targets isn't scoped to any; suggest_fix/raise_fix_pr are
    scoped to a finding); left blank rather than forced to a sentinel."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    agent: str = "unknown"
    tool: str = Field(index=True)  # "list_targets", "raise_fix_pr", ...
    summary: str = ""
    target_id: Optional[int] = Field(default=None, foreign_key="target.id")
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    success: bool = True
    error: str = ""
    created_at: datetime = Field(default_factory=utcnow, index=True)


class ToolInstallRun(SQLModel, table=True):
    """One admin-triggered scanner install (#216).

    Same create-row-then-dispatch-via-.delay() shape as Scan/DiscoveryRun, so
    `mark_stale_if_needed` and the frontend's poll-until-settled helper both
    work on it unchanged.

    It doubles as the audit record: there is no generic audit table in this
    project (the audit feed is derived from FindingStateLog/Scan), and
    "who installed what, when, and did it work" is exactly what an operator
    needs after the fact for an action that mutates the running environment.
    `requested_by_user_id` is therefore not optional in spirit; an install
    with no attributable actor would defeat the point.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    tool: str = Field(index=True)
    # Recorded as resolved at dispatch time rather than looked up later: the
    # registry can change under a historical row, and the audit record should
    # say what was actually installed, not what would be installed today.
    package: str
    status: str = "running"  # running, completed, failed
    requested_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    # Version reported by the tool's own version_cmd *after* installing;
    # proof it actually runs, not just that pip exited zero.
    installed_version: str = ""
    error: str = ""
    # Tail of pip's output. Bounded before write (see tool_install.py): pip
    # can emit megabytes on a big dependency tree, and this is a display aid,
    # not a build log.
    output_tail: str = ""


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

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    mitigated_at: Optional[datetime] = None
    # SLA-breach notification dedup (issue #73): set the first time this
    # finding is observed to be sla_violated at a query-time check (see
    # app.api.findings._maybe_notify_sla_breach), so the same violation
    # doesn't re-fire a Slack message on every subsequent GET. Reset to None
    # if the finding is later mitigated/reopened past its SLA again would be
    # a fresh breach; see _maybe_notify_sla_breach for the reset rule.
    sla_breach_notified_at: Optional[datetime] = None


class CveEnrichment(SQLModel, table=True):
    """Locally-cached, AI-free enrichment for a single CVE ID (issue #71),
    sourced from NVD (description/CVSS/CWE) and OSV.dev (known fixed
    versions), explicitly *not* the AI Analysis feature (`app/api/ai.py`),
    so this must work with zero AI provider configured.

    NVD/OSV data for a given published CVE is effectively immutable, unlike
    KEV's whole-catalog daily refresh (`core/kev.py`) or EPSS's score that
    genuinely changes over time, a real DB row cached "forever" (fetched
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

    # (#201) The CVSS vector above, decomposed into the four exploitability
    # metrics the risk-scoring engine consumes; see app/core/cvss.py for the
    # parser and app/core/scoring.py for the signal slot they feed.
    #
    # A denormalisation of `cvss_vector`, not an independent source of
    # truth: parse_cvss_vector() is authoritative, these columns are what it
    # produced, written when the row is fetched and backfilled on read for
    # rows that predate this (see app/core/cve_enrichment.py). Persisted
    # rather than parsed per request so the decomposition is visible in the
    # API and queryable -- "show me everything network-reachable with no
    # privileges required" is a filter, not a computation.
    #
    # NULL everywhere means "not established", which is NOT the same as a
    # benign value and must never be scored as one. That is why there is no
    # "unknown" sentinel string: a column that is either a real CVSS value or
    # NULL cannot accidentally be compared as if unknown were a metric value.
    cvss_version: Optional[str] = None              # "3.1", "4.0", "2.0", ...
    cvss_attack_vector: Optional[str] = None        # network / adjacent / local / physical
    cvss_attack_complexity: Optional[str] = None    # low / medium / high
    cvss_privileges_required: Optional[str] = None  # none / low / high
    cvss_user_interaction: Optional[str] = None     # none / passive / required / active

    # OSV.dev (https://osv.dev/docs); queried directly by CVE ID via
    # GET /v1/vulns/{cve_id}, which resolves CVE as an alias without needing
    # package/ecosystem context.
    osv_id: Optional[str] = None
    fixed_versions: Optional[str] = None  # JSON-encoded list[dict] (package/ecosystem/fixed)
    osv_references: Optional[str] = None  # JSON-encoded list[str] of URLs
    osv_found: bool = Field(default=False)

    fetched_at: datetime = Field(default_factory=utcnow)


class EncryptionKeyCanary(SQLModel, table=True):
    """Single-row marker used to detect a PLATFORM_ENCRYPTION_KEY mismatch
    proactively at startup, instead of discovering it as a cryptic decrypt
    failure buried inside whichever feature (Mass Rollout, Slack, Jira, SIEM,
    AI key) happens to touch an encrypted secret first.

    Holds one known plaintext, encrypted under whatever key is currently
    configured. On every boot, app.core.crypto.check_encryption_key_health
    tries to decrypt this row with the *current* key: success proves the
    running key is the same one that encrypted every other secret in this
    database (GitHubAppConfig.private_key_pem, PlatformConfig's webhook
    URLs/API keys, ...); failure proves it changed since, which means every
    one of those secrets is now permanently undecryptable (Fernet is
    deliberately one-way; there is no way to recover a value encrypted
    under a lost key).

    Never overwritten automatically on a mismatch; see
    app.core.crypto.reseed_encryption_key_canary, only called from the
    explicit admin-triggered "I've reconnected everything" action in
    Admin > Global Integrations, once every affected integration has
    actually been reconnected under the new key."""
    id: Optional[int] = Field(default=None, primary_key=True)
    ciphertext: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class PlatformConfig(SQLModel, table=True):
    """Single-row runtime configuration, editable via Admin > Global Integrations."""
    id: Optional[int] = Field(default=None, primary_key=True)
    anthropic_api_key: Optional[str] = None
    # AI Analysis provider selection: "anthropic" (default) or "openai_compatible".
    # The openai_compatible fields cover any self-hosted/OpenAI-compatible chat
    # completions endpoint, Kimi/Moonshot, Ollama, vLLM, LM Studio, etc.
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
    # same pattern as openai_compatible_api_key above; a webhook URL is a
    # bearer credential (anyone with it can post to the channel).
    slack_webhook_url: str = ""
    # Jira API config (issue #74): server URL (e.g.
    # "https://yourorg.atlassian.net"), an API token (encrypted, same pattern
    # as the webhook URL/openai key above), the project key issues get
    # created under (e.g. "SEC"), and the issue type name (e.g. "Bug",
    # "Task"); both project key and issue type are plain strings, not
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
    # single scalar rather than a rule table for this first version; see
    # PolicyRule/SlaRule for the shape a future multi-rule version could grow
    # into if needed.
    jira_auto_create_severity: Optional[str] = None
    # SIEM export (issue #114): a generic outbound webhook; one JSON POST
    # per net-new finding at or above the configured severity threshold, the
    # same shape virtually every SIEM/log pipeline can ingest (Splunk HEC,
    # Elastic/Datadog generic webhook input, or a plain middleware relay);
    # deliberately not one specific vendor's proprietary wire format for this
    # first version. Encrypted at rest, same pattern as slack_webhook_url;
    # a webhook URL is a bearer credential. Auto-export threshold mirrors
    # jira_auto_create_severity's single-scalar shape exactly (same
    # "start simple, grow into a rule table only if needed" reasoning).
    siem_webhook_url: str = ""
    siem_export_severity: Optional[str] = None
    updated_at: datetime = Field(default_factory=utcnow)


class GitHubAppConfig(SQLModel, table=True):
    """One row per registered GitHub App (multi-install support, #34); a
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
    for rows created before this column existed (pre-#34); those are
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
    # Which GitHub account owns this App -- "User" (github.com/settings/apps/
    # {slug}) or "Organization" (github.com/organizations/{owner_login}/
    # settings/apps/{slug}). GitHub's manifest-conversion response includes
    # this (`data["owner"]`); an App created for an org (manifest-data's own
    # `org` param) is owned by that org, not by the user who clicked through
    # the flow, so the two URL shapes aren't interchangeable -- the
    # connect-github-card.tsx "Manage on GitHub" link 404s if it guesses
    # wrong. Nullable for rows created before this column existed; those are
    # backfilled lazily via GET /app (see app.api.github_app.status).
    owner_login: Optional[str] = None
    owner_type: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


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
    created_at: datetime = Field(default_factory=utcnow)


class GitHubToken(SQLModel, table=True):
    """Per-workspace GitHub credential (issue #227): a user-supplied personal
    access token, encrypted at rest via app.core.crypto.encrypt_secret and
    never echoed back to the client (the API reports only ``token_set`` /
    ``expires_at`` / ``created_at``). One active token per workspace (unique
    ``workspace_id``), saving replaces the existing row.

    ``expires_at`` (nullable = never expires) is the TTL the operator chose at
    save time. Purge is lazy (see app.core.github_token.resolve_github_token):
    an expired token is hard-deleted on first read after expiry, consistent
    with the project's no-Celery-beat design (app/core/staleness.py, #153).

    Reversible encryption (not a one-way hash) is required here, unlike
    ApiToken: a GitHub PAT must be *replayed* to GitHub on the user's behalf,
    so it can't be stored hashed; the same reason GitHubAppConfig's
    client_secret/private_key_pem are encrypted rather than hashed.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", unique=True, index=True)
    token_ciphertext: str
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = None


class FindingStateLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    from_state: str
    to_state: str
    reason: str = ""
    actor: str = "system"
    created_at: datetime = Field(default_factory=utcnow)
    # Issue #123: a bulk-triage call (findings.bulk_triage_findings) still
    # writes one row per finding here, that's the right granularity for
    # per-finding history (finding_history reads it unfiltered), but tags
    # every row from the same call with a shared batch_id so the Audit Log
    # can collapse them into a single "N findings ..." feed item at read
    # time instead of flooding the feed with near-identical rows. Nullable:
    # single-finding triages (and every row written before this column
    # existed) have no batch and are never grouped.
    batch_id: Optional[str] = Field(default=None, index=True)


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
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    # Operator-declared scope for ACTIVE scanning (#469). An excluded
    # endpoint is never sent to nuclei, not even when a caller names it
    # explicitly in endpoint_ids -- it is a standing "do not touch this",
    # typically because hitting it does something destructive or expensive
    # that no scanner should trigger. Discovery keeps re-seeing and
    # re-upserting the endpoint; only its scannability changes.
    excluded: bool = Field(default=False, index=True)
    exclusion_reason: Optional[str] = None


class DiscoveryRun(SQLModel, table=True):
    """Tracks a single async API Discovery run dispatched via Celery (#59).

    POST /api/discovery/{target_id} used to clone+grep synchronously inside
    the request handler; a handful of concurrent requests could exhaust
    FastAPI's threadpool. Now the endpoint creates this row, dispatches
    app.tasks.discovery_tasks.run_discovery via .delay(), and returns
    immediately with this row's id; the frontend polls
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
    # Comma-separated ApiEndpoint ids that were net-new on this specific run;
    # lets GET .../runs/{run_id} report accurate per-endpoint is_new flags
    # (mirroring what the old synchronous POST response used to compute
    # inline) without guessing from timestamps after the fact.
    new_ids: str = ""
    started_at: datetime = Field(default_factory=utcnow)
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
    # (#227, raised by @r0075h3ll) Which source reported this component:
    # "github", "upload", or "github,upload" when both did.
    #
    # Recorded rather than discarded because the two sources genuinely see
    # different things; GitHub's Dependency Graph reports what a manifest
    # resolves to (including transitives that appear in no manifest at all),
    # an uploaded SBOM reports whatever the uploader's tooling found. "Only
    # upload found this" is a real provenance signal worth keeping.
    #
    # The model-level default is "github", the only source that now writes
    # rows automatically; there is no DB-level default and no migration, and
    # every upsert_components caller passes source= explicitly, so it is a
    # statement of intent rather than a value rows actually take. Rows
    # written before #328 removed trivy SBOM generation keep the "trivy" the
    # #227 migration backfilled; they are not relabelled as confirmed by a
    # source that never saw them.
    source: str = "github"
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class AiBomComponent(SQLModel, table=True):
    """A model or dataset a target depends on (issue #190).

    Deliberately a separate table from SbomComponent rather than a `kind`
    column on it. They are different things with different keys: an
    SbomComponent is a resolved package at a concrete version from a
    lockfile, an AiBomComponent is a *reference* to a model or dataset whose
    version is very often genuinely unknown. Sharing a table would force
    either nullable columns that mean different things per row, or a fake
    version on every model; and fabricating a version is precisely what
    this feature exists not to do.

    Populated during the existing SBOM generation run, which already has a
    checkout (app/tasks/sbom_tasks.py), so no extra clone.
    """

    # This index is the upsert key app.core.aibom.upsert_aibom_components keys
    # on: a model is identified by target + branch + name + type. Version is
    # deliberately NOT part of it -- an unpinned reference that later gains a
    # revision is the same dependency, now pinned, not a new one.
    #
    # It is declared here, and not only in the migration that created it
    # (alembic/versions/3d006423f58b_add_aibom_components_190.py), because a
    # unique index that exists in the database but not in the model metadata
    # is invisible to Alembic's comparison: `--autogenerate` sees an index in
    # the database that nothing in metadata accounts for and emits
    # `op.drop_index('ix_aibomcomponent_upsert_key')`. That was one of the
    # unrelated operations #217 found sitting in generated migrations. Keep
    # this declaration in step with the migration; the guard for it is
    # tests/test_schema_drift.py.
    __table_args__ = (
        Index(
            "ix_aibomcomponent_upsert_key",
            "target_id",
            "branch",
            "name",
            "component_type",
            unique=True,
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    name: str
    # "machine-learning-model" or "data", CycloneDX 1.6 component types.
    component_type: str
    # "unknown" when the reference carries no pinned revision. Stored as the
    # literal string rather than NULL so a reader sees the field was
    # considered; see app.core.aibom.UNKNOWN.
    version: str = "unknown"
    # huggingface / hosted-api / local
    source: str = "unknown"
    # Comma-separated repo-relative paths this reference was found in, so an
    # over-inclusive row can be judged and dismissed rather than argued with.
    evidence: str = ""
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class SbomRun(SQLModel, table=True):
    """Tracks a single async SBOM generation run dispatched via Celery
    (#59), same running/completed/failed lifecycle as DiscoveryRun above,
    for POST /api/sbom/{target_id}."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    branch: str
    status: str = "running"  # running, completed, failed
    error: str = ""
    count: int = 0
    new_count: int = 0
    # Comma-separated SbomComponent ids that were net-new on this run,
    # same rationale as DiscoveryRun.new_ids above.
    new_ids: str = ""
    # (#227) Which SBOM sources actually contributed to this run, and which
    # were attempted but could not answer. Same three-state discipline as
    # PRGuardrailScan.tools_run/tools_failed (#243, #253): GitHub's
    # Dependency Graph returning nothing because it is disabled for a
    # private repo is NOT the same fact as a repo genuinely having no
    # dependencies, and an inventory that cannot tell those apart is the
    # false-all-clear shape this codebase keeps refusing.
    #
    # Empty until a source actually answers: a row is created with
    # status="running" before the task starts, and a run that fails before
    # any source contributes must not read as one where GitHub did.
    sources_run: str = ""
    sources_failed: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None


class PRGuardrailScan(SQLModel, table=True):
    """A PR Guardrail diff-scan run (architecture doc Flow C).

    Net-new findings from this run are NOT persisted as platform Finding rows
    (that would pollute default-branch posture with PR-branch-only noise);
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
    # Which tools this scan actually ran, and which were assigned but failed
    # (comma-separated, registry order). Before GH-01 the guardrail hardcoded
    # semgrep, so "what got checked" was an invisible constant; now that the
    # set is operator-configurable per workspace, a scan that reports "no new
    # findings" has to be able to say *what it looked with*. tools_failed
    # being non-empty is why a scan can be ERROR while still carrying real
    # findings from the tools that did run; a partial check must never
    # render as a clean pass.
    tools_run: str = ""
    tools_failed: str = ""
    # (#243) Tools that had nothing to examine once the scan was scoped to
    # the PR's changed files, trivy when no dependency manifest changed,
    # tfsec when no Terraform did. A third column rather than a note folded
    # into tools_run, because "skipped" and "ran clean" are different claims
    # and only one of them is evidence of safety.
    tools_skipped: str = ""
    # (#243) How much of the repo this scan actually looked at: "full" (the
    # whole checkout) or "diff" (only the PR's changed files). Persisted, not
    # derived, so the PR comment and the audit trail can state the scope of
    # the assurance being offered rather than implying whole-repo coverage.
    scan_scope: str = "full"
    files_scanned: int = 0  # meaningful only when scan_scope == "diff"
    # (#244) How many of files_scanned were pulled in by the code graph
    # rather than literally changed by the PR -- the blast radius. 0 with
    # scan_scope "diff" means the changed files import nothing else in this
    # repo (or are not Python, which the Stage 1 graph cannot follow), not
    # that the radius went unchecked; scope_reason carries that distinction.
    blast_radius_files: int = 0
    # (#244) Why the scope ended up as it did, in the words the PR comment
    # uses. Persisted rather than recomputed because the graph it was
    # derived from is replaced on the next scan -- without this, the audit
    # trail could no longer explain a past scan's coverage.
    scope_reason: str = ""
    # (GH-04) Why the commit status did not reach GitHub, or "" if it did.
    # Posting is deliberately fail-open (a GitHub outage must not abort a
    # scan that already produced real findings) but it used to be fail-open
    # *and silent*, into a container log. If an installation token breaks,
    # PRs quietly stop being marked and nobody is told. Persisted so PR
    # History can show "the decision never reached GitHub" next to the
    # decision itself.
    status_delivery_error: str = ""
    # (GH-07) True when this scan's finding diff had no completed baseline
    # scan of the target's default branch to compare against. Same "no
    # baseline is not zero, it's unknown" distinction GH-06 already applies
    # to the endpoint diff (see _diff_new_endpoints): an empty existing_hashes
    # set because the default branch was never scanned looks identical, at
    # the query level, to one that's empty because everything was fixed.
    # Diffing against it anyway reports the whole repository's pre-existing
    # state as introduced by whichever PR happens to be scanned first.
    # Persisted (not just logged) so the PR comment and PR History can say
    # plainly that this scan's "no findings" is not yet a real diff.
    baseline_missing: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None


class IgnoreStatus(str, Enum):
    NONE = "none"
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    # A previously-approved ignore that a reviewer later undid (see
    # revoke_ignore, app/api/pr_guardrail.py). Deliberately its own terminal
    # state rather than resetting back to NONE: a finding a reviewer never
    # looked at and one whose approval was explicitly walked back are
    # different facts, and the Approval Queue's History tab needs to keep
    # showing the latter rather than having it silently vanish from the
    # record the moment it's revoked.
    REVOKED = "revoked"


class PRGuardrailFinding(SQLModel, table=True):
    """One net-new finding from a PRGuardrailScan, persisted so it can be
    deep-linked from the GitHub PR comment back into the platform and carry
    its own ignore-request/approval state (developer requests, security
    engineer or admin approves/rejects; see app/api/pr_guardrail.py)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    pr_scan_id: int = Field(foreign_key="prguardrailscan.id", index=True)
    tool: str
    rule_id: str
    title: str
    file_path: str
    line_start: int | None = None
    severity: str  # "Critical"/"High"/etc, stored as str, not Severity, since these aren't platform Findings

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
    .delay(), and returns immediately with this row's id; the frontend
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
    # #245's double-scan gap: server-side PR Guardrail already scans every
    # PR once GitHub can reach this backend (app.api.github_app.
    # webhook_reachable), so Pipeline Integration adds a redundant second
    # scan of the same PRs on top of it. `force` is the batch-level opt-in
    # to that redundancy anyway (set from the request; see
    # BulkPipelineIntegrateRequest.force / MassPipelineRolloutRequest.force);
    # `skipped_webhook_reachable` counts items run_pipeline_integration_batch
    # skipped for this reason instead of a failure or a success, mirroring
    # `already_integrated` above.
    force: bool = False
    skipped_webhook_reachable: int = 0
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    # Issue #35 (Mass CI/CD Rollout Engine): this batch table, originally
    # #68's manual multi-select wrapper, is reused verbatim for scope-based
    # "mass rollout" (by group/workspace/all-accessible); see
    # POST /api/targets/mass-pipeline-rollout. `scope_label` is a
    # human-readable description of how the target set was resolved (e.g.
    # "Workspace: acme-prod", "Group: pci-scope", "All accessible repos")
    # for display on a batch that wasn't built from an explicit checkbox
    # selection; "" for #68's original manual-selection batches.
    scope_label: str = ""
    # Custom Workflow Builder (#35): which PipelineWorkflowTemplate's step
    # list to use when generating each item's workflow YAML, instead of
    # #66's fixed semgrep/gitleaks/trivy(+gosec) default. Null means "use
    # the default template", #68's existing manual bulk-integrate flow
    # never sets this, so it keeps its original behavior unchanged.
    workflow_template_id: Optional[int] = Field(default=None, foreign_key="pipelineworkflowtemplate.id")


class PipelineIntegrationBatchItem(SQLModel, table=True):
    """One target's outcome within a PipelineIntegrationBatch (#68). Each
    item involves a real GitHub API call (branch create + content write +
    PR open, via #66's open_pipeline_pr); the Celery task processes items
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


class PipelineWorkflowTemplate(SQLModel, table=True):
    """Custom Workflow Builder (issue #35): a workspace-scoped, named,
    ordered step list over the fixed scanner catalog #66's default template
    hardcodes (semgrep/gitleaks/trivy/gosec); lets a user compose *which*
    scanners run and in what order, instead of always getting the fixed
    default set. Deliberately a structured step-list editor over a small
    known catalog (toggle + reorder), not a full drag-and-drop arbitrary-DAG
    builder; that's future work if ever needed, out of scope for a first
    version per the issue.

    `steps` is an ordered JSON list of ``{"tool": "semgrep", "enabled":
    true}`` dicts (see `app.core.pipeline_workflow.SUPPORTED_TOOLS` for the
    valid `tool` values); `app.core.pipeline_workflow.generate_workflow_yaml`
    consumes the enabled subset directly, in list order. A workspace can
    hold several named templates (e.g. "Fast" vs "Full audit") and pick one
    at rollout time via `PipelineIntegrationBatch.workflow_template_id`."""
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    name: str
    steps: list = Field(sa_column=Column(JSON), default_factory=list)
    created_by_user_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


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
    created_at: datetime = Field(default_factory=utcnow)
    active: bool = True


class SlaRule(SQLModel, table=True):
    """A workspace-scoped SLA (days-to-fix) rule, keyed by severity and
    optionally a repo Group (issue #70); e.g. "Critical findings in the
    'production' group must be fixed within 7 days", or a workspace-wide
    default of "Medium findings get 30 days" for targets with no
    group-specific rule.

    Unlike #62's enforcement_mode (a single inherited scalar per level),
    an SLA is naturally a matrix of (group-or-workspace-default, severity)
    -> days_to_fix, since "Critical" and "Low" need very different windows
    even within the same group. group_id is nullable: NULL means
    "workspace-default", applied to a target only when none of its groups
    carry a rule for that severity; see
    app.core.sla.resolve_sla_days for the group -> workspace-default -> "no
    SLA" resolution (deliberately not the enforcement.py 3-level target ->
    group -> workspace chain, since there's no per-target SLA override in
    this first version; targets inherit purely through their group(s)).

    The (workspace_id, group_id, severity) unique constraint is the intended
    shape of "at most one rule per group+severity, and at most one workspace
    default per severity"; note Postgres treats NULL as distinct for
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
    created_at: datetime = Field(default_factory=utcnow)


class ScanScheduleType(str, Enum):
    """Which kind of scan a ScanSchedule row drives (issue #306).

    Deliberately NOT a tool name. A schedule says "keep this target's
    posture fresh", not "run semgrep"; which tools that actually means is
    already a per-workspace decision (`WorkspaceToolConfig`/#75, resolved by
    `app.core.tool_usage.tools_for_surface`). Encoding tool names here would
    give an operator two places to turn the same scanner off and no rule for
    which one wins.
    """
    # Every on_demand_scan-enabled SAST/SCA tool against the default branch,
    # dispatched via app.tasks.scan_tasks.queue_full_scan (the same path the
    # "Scan now" button and the GitHub App import already use).
    FULL_SCAN = "full_scan"
    # Active API scanning (nuclei, #72) against the endpoints already
    # discovered for this target, dispatched via
    # app.tasks.api_scan_tasks.queue_api_scan. Only ever reaches a host the
    # target's owner explicitly declared in Target.api_base_url.
    API_SCAN = "api_scan"


class ScanSchedule(SQLModel, table=True):
    """A configurable scan cadence (issue #306), stored as data instead of
    the two hardcoded ``timedelta(hours=24)`` entries that used to live in
    ``celery_app.conf.beat_schedule``.

    Two scopes, following the same NULL-means-inherit convention SlaRule
    (#70) uses for ``group_id`` and Workspace/Group/Target
    ``enforcement_mode`` (#62) use for their override columns:

      * ``target_id`` NULL  -> the workspace default for this scan type,
        applied to every target in the workspace that has no row of its own.
      * ``target_id`` set    -> this one target's override; it stops being
        covered by the workspace-default row entirely.

    The two *value* columns inherit independently and at field level, so a
    target can say "disabled" without also having to pin an interval, or
    "every 6 hours" while inheriting enabled-ness:

      * ``enabled`` NULL         -> inherit (workspace default, then the
        shipped default in app.core.scan_schedules.SHIPPED_DEFAULTS).
      * ``interval_hours`` NULL  -> same.

    ``last_run_at``/``next_run_at`` are what make the beat dispatcher safe
    across a restart, and they are deliberately two columns rather than one
    derived value:

      * ``next_run_at`` is the due-ness clock. It lives in the database, so
        restarting Beat cannot re-arm a schedule that already fired (the old
        hardcoded 24h entry had the opposite problem: Beat records a fresh
        interval schedule's *creation* time as its last run, so a deploy
        every 12h meant the 24h entry never fired at all).
      * ``last_run_at`` is the honesty column. NULL means "this schedule has
        never actually fired", which is a real state a fresh install spends
        its first interval in, and the UI must say so rather than rendering
        an empty cell that reads like "nothing to see here". It is never
        seeded at creation time for exactly that reason.

    ``last_dispatched_count`` keeps the same distinction one level down: a
    schedule that fired and dispatched zero scans (every covered target was
    unconfigured for active API scanning, say) is not the same as one that
    never fired, and neither is the same as one that dispatched five.
    """
    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "target_id", "scan_type", name="uq_scan_schedule_workspace_target_type"
        ),
        # The constraint above cannot police the workspace-default rows,
        # because Postgres treats NULL as distinct for uniqueness: two rows
        # with target_id NULL, the same workspace and the same scan_type do
        # not collide under it. That is not a cosmetic gap here. Both rows
        # would pass due_schedules, both would cover every target in the
        # workspace, and every target would be scanned twice per cycle
        # forever -- while every read path (which takes .first()) kept
        # showing exactly one healthy schedule, so nothing would ever
        # surface it.
        #
        # SlaRule documents the same NULL gap and answers it with a
        # lookup-then-write API guard. That is not enough for this table:
        # the row that matters is created by ensure_workspace_default_rows
        # running unattended every few minutes on every worker, where a
        # lookup-then-insert is a real check-then-act race rather than a
        # theoretical one. So it is enforced in the schema instead, as a
        # partial unique index. Both dialects are spelled out because tests
        # build this table from the model metadata on SQLite while
        # deployments get it from the Alembic migration on Postgres, and an
        # invariant that only exists in production is one nothing catches.
        Index(
            "uq_scan_schedule_workspace_default",
            "workspace_id",
            "scan_type",
            unique=True,
            postgresql_where=text("target_id IS NULL"),
            sqlite_where=text("target_id IS NULL"),
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    # NULL = the workspace-wide default for this scan type; kept unique by
    # the partial index above, not by the UniqueConstraint.
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    scan_type: ScanScheduleType = Field(index=True)
    interval_hours: Optional[int] = None
    enabled: Optional[bool] = None
    # NULL = never fired. See the class docstring; this is load-bearing for
    # the UI, not just bookkeeping.
    last_run_at: Optional[datetime] = None
    last_dispatched_count: Optional[int] = None
    # NULL would mean "due on the next dispatcher tick". In practice every
    # write path sets this explicitly (creation and any enable/interval
    # change set it to now + the effective interval, so switching a schedule
    # on never triggers an immediate fan-out across every target); the
    # nullable column is the safe reading for a row written by something
    # that forgot to.
    next_run_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ScoringSignal(str, Enum):
    """The fixed signal slots the risk-prioritisation engine scores on
    (#201).

    Deliberately a closed enum rather than a rules DSL. The issue asks for
    "configurable weights with shipped baselines", and #69's widget catalog
    settled the same argument the same way: a concrete set of things the
    platform actually knows how to compute, each of which can be turned up
    or down, beats an expression language that can express anything and
    explain nothing. Every slot here is a signal this codebase already has
    real data for; adding one means writing the code that derives it, which
    is exactly the gate that keeps the breakdown honest.

    What is deliberately NOT here: first-party reachability. That is phase 3
    of #201 and depends on #183, an unresolved design spike. Shipping an
    inert `reachability` slot would advertise a signal nothing computes, and
    a weight that does nothing is worse than an absent one -- someone would
    set it and believe their scores accounted for reachability.
    """

    SEVERITY = "severity"                            # base tool severity (1-5)
    CVSS_EXPLOITABILITY = "cvss_exploitability"      # decomposed AV/AC/PR/UI (CVE-backed findings)
    EPSS = "epss"                                    # predicted 30-day exploit probability
    KEV = "kev"                                      # CISA Known Exploited Vulnerabilities
    INTERNET_EXPOSURE = "internet_exposure"          # Target.label / Target.environment
    BUSINESS_CRITICALITY = "business_criticality"    # Target.criticality_weight + #251 metadata
    FIXABILITY = "fixability"                        # #246: can this be closed today


class ScoringWeight(SQLModel, table=True):
    """A workspace-scoped weight for one scoring signal slot (#201).

    Same shape as SlaRule/PolicyRule: workspace-scoped rows, one per
    (workspace, signal), created only when someone actually overrides
    something. Absence of a row means "use the shipped baseline" -- the same
    "None = inherit" philosophy as WorkspaceToolConfig (#75) and
    Workspace/Group/Target.enforcement_mode (#62), rather than requiring
    every workspace to enumerate every signal before any of them apply. The
    practical consequence is the one the issue asks for: an install that
    configures nothing scores exactly as it did before this table existed.
    See app.core.scoring.BASELINE_WEIGHTS for those defaults and why the
    three new signals baseline at 0.0.

    `weight` is a multiplier on that signal's contribution, not a point
    value; 1.0 is the shipped baseline behaviour for a signal that ships on,
    0.0 switches the signal off entirely. Clamped to >= 0 at both the API
    boundary and in the scoring engine, which is what structurally
    guarantees the issue's hard rule: no signal can ever *subtract* from a
    priority, so an unknown or absent signal can never lower one either.
    """

    __table_args__ = (
        UniqueConstraint("workspace_id", "signal", name="uq_scoring_weight_workspace_signal"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    signal: ScoringSignal = Field(index=True)
    weight: float
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class WorkspaceToolConfig(SQLModel, table=True):
    """Per-workspace, per-tool usage assignment (issue #75): which of the
    tool registry's four usage surfaces (`app.core.tool_registry.
    USAGE_SURFACES`) a given scanner is enabled for in this workspace,
    on-demand ("Scan now" from the Targets page), CI pipeline (the
    generated GitHub Actions workflow from #66/pipeline_workflow.py),
    active API scanning (#72, not yet wired to actually read this flag;
    the column exists now so the assignment UI has one stable place to
    grow into once #72 ships), and PR Guardrail diff scans.

    Absence of a row for a (workspace_id, tool) pair means "use the
    built-in default", not "disabled"; see
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
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class NotificationChannel(str, Enum):
    """Delivery channel for a NotificationPreference (issue #73). `slack`
    posts to the single platform-wide webhook configured in
    PlatformConfig.slack_webhook_url (#74), there's no per-user Slack
    OAuth/DM capability in this project, so a user "enabling Slack" means
    "mention me in the message posted to the platform's configured Slack
    channel", not a private DM. `email` has a preference row so a user's
    intent is recorded, but there is deliberately no real SMTP/email-sending
    infrastructure anywhere in this codebase yet; see
    app.core.notifications.dispatch_notification, which no-ops (with a clear
    log line) for this channel rather than fabricating a delivery."""
    EMAIL = "email"
    SLACK = "slack"


class NotificationEventType(str, Enum):
    """What can trigger a notification (issue #73). See
    app.core.notifications for where each of these actually fires:
    critical_finding/kev_cve at ingestion time (app.core.ingestion, same
    hook point as #74's Jira auto-create), sla_breach at the query-time
    point #70 already computes SLA violation (app.api.findings),
    scan_failure when a Scan/DiscoveryRun/SbomRun transitions to status
    "failed" (app.tasks.*), and malicious_package when a net-new finding is
    a malicious dependency (tool="osv-malware", #179)."""
    CRITICAL_FINDING = "critical_finding"
    KEV_CVE = "kev_cve"
    SLA_BREACH = "sla_breach"
    SCAN_FAILURE = "scan_failure"
    MALICIOUS_PACKAGE = "malicious_package"


class NotificationPreference(SQLModel, table=True):
    """One user's opt-in for one (channel, event_type) pair (issue #73).
    Absence of a row means "not enabled", there's no default-on behavior,
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
    created_at: datetime = Field(default_factory=utcnow)


class FalsePositiveRule(SQLModel, table=True):
    """A learned suppression rule (issue #76), created automatically the
    moment a user triages a Finding to FindingState.FALSE_POSITIVE (see
    app.core.fp_learning.learn_suppression_rule, called from
    app.core.triage.apply_triage) and consumed at ingestion time
    (app.core.ingestion.ingest_findings) to auto-suppress newly-created
    Findings that match the same signature; so the same false positive
    doesn't have to be re-triaged every time it reappears, including in a
    *different* repo (ROADMAP's "cross-repo suppression").

    Scoped to `workspace_id`, not a single Target; a Workspace already
    groups multiple repos (Targets) in this codebase (see Target.workspace_id
    everywhere else), so "cross-repo within an org" in practice means
    "matches any Target under this workspace", the same granularity
    PolicyRule/SlaRule already use for workspace-wide config. True
    cross-*workspace* suppression isn't implemented in this first version,
    consistent with this codebase's existing single-tenant-per-Organization
    shape (Organization -> Workspace -> Target) where nothing else reaches
    across workspace boundaries either.

    Signature = (rule_id, tool, file_path_pattern). rule_id/tool are exact
    matches against the scanner's own rule_id/tool (same fields Finding
    already carries and PolicyRule.SUPPRESS_RULE already keys off).
    file_path_pattern is the *basename* of the file the false positive was
    found in (e.g. "settings.py", not "backend/app/core/settings.py"),
    deliberately not the full path, since an identical full path recurring
    in a *different* repo would be the exception rather than the rule,
    while the same filename (test fixtures, generated code, vendored
    dependencies, common config filenames) recurring across repos is a very
    common real false-positive shape. NULL means "any file", the broadest
    form, settable via PATCH by a security engineer/admin who wants to widen
    an existing rule rather than only narrow/revoke it.

    Deliberately no snippet_hash field (even though the issue text mentions
    one as optional): Finding never persists the raw matched code snippet
    anywhere in this codebase (app.core.dedup.compute_dedup_hash consumes it
    only to produce a one-way SHA-256 dedup_hash); there is nothing to
    re-derive a comparable snippet signature from for an already-ingested
    Finding, so a snippet_hash field would be permanently unpopulated dead
    weight rather than a real second signal. rule_id + tool + file_path
    basename is the real, honest signature this codebase can support today.

    Soft-revocable via `active` (same pattern as PolicyRule) rather than
    hard-deleted by default; DELETE is still offered for real removal, but
    PATCH .../active lets a security engineer "expire" a rule (stop it
    firing) while keeping the audit trail of what it used to suppress and
    how many times, which a hard delete would destroy.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    rule_id: str = Field(index=True)
    tool: str
    file_path_pattern: Optional[str] = None

    # Audit trail: which Finding/triage action originally taught this rule,
    # and who (actor string, same free-text convention as
    # FindingStateLog.actor, "user"/"system"/etc, not a User FK, since
    # bulk-triage's actor is caller-supplied free text too).
    source_finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    created_by: str = "system"
    created_at: datetime = Field(default_factory=utcnow)

    active: bool = True
    # Incremented + stamped every time app.core.ingestion.ingest_findings
    # auto-suppresses a new Finding against this rule, feeds both the
    # per-rule "fired N times" UI and (via Finding.state_reason's matching
    # marker string, see fp_learning.AUTO_SUPPRESS_REASON_PREFIX) the
    # dashboard's "X findings auto-suppressed this month" figure without
    # needing a second event-log table.
    match_count: int = 0
    last_matched_at: Optional[datetime] = None


class DashboardLayout(SQLModel, table=True):
    """A user's configurable dashboard composition (issue #69), replacing
    the previous single fixed layout in frontend/(dashboard)/page.tsx.

    `widgets` is an ordered JSON list of widget *instances*:
    ``[{"id": "<uuid>", "widget_id": "kpi_cards", "config": {...}}, ...]``.
    `id` is a per-instance identifier (stable across reorders/renames so the
    frontend can key React lists and target a specific instance for
    remove/move, distinct from `widget_id` which names the concrete widget
    *type* in app.core.widgets.WIDGET_CATALOG). `config` is deliberately
    minimal, a widget's own scope filter (e.g. `{"limit": 10}` for recent
    findings), not a generic arbitrary-chart-config blob; see
    app.core.widgets for the concrete (non-generic) widget catalog this
    project chose instead of a build-your-own-chart system.

    One row per user (unique user_id); absence of a row means "no custom
    layout saved yet", resolved by GET /api/dashboard/layout to
    app.core.widgets.build_default_layout()'s sensible default set rather
    than an empty dashboard.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", unique=True, index=True)
    widgets: list = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    updated_at: datetime = Field(default_factory=utcnow)


class AiAnalysisRun(SQLModel, table=True):
    """Issue #122: minimal tracking of "which findings has this user run AI
    analysis on", so the AI Analysis page has a real "recent analyses"
    landing state instead of only being reachable via a deep link. This is
    deliberately not a full audit trail (no stored analysis text, no
    per-request history); one row per (user, finding), upserted on every
    POST /api/ai/analyze/{finding_id}: `last_analyzed_at` is bumped on
    repeat analysis of the same finding rather than inserting a new row, so
    "recent analyses" reflects the finding's most recent analysis time, not
    a growing log. `analysis_count` is incidental (not surfaced yet) but
    cheap to keep for a future "analyzed N times" affordance."""

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    created_at: datetime = Field(default_factory=utcnow)
    last_analyzed_at: datetime = Field(default_factory=utcnow, index=True)
    analysis_count: int = 1

    __table_args__ = (UniqueConstraint("user_id", "finding_id", name="uq_ai_analysis_run_user_finding"),)


class ApiTokenScope(str, Enum):
    READ = "read"
    READ_WRITE = "read_write"


class ApiToken(SQLModel, table=True):
    """Issue #109: a user-issued Personal Access Token for the public API
    (`/api/public/v1/*`), distinct from `Workspace.api_key`; that key is a
    single, un-scoped, CI-ingest-only secret shared by the whole workspace
    (`POST /api/ingest/{target_id}`); this is a per-user, named, revocable
    token for third-party/scripted read (and optionally write) access.

    Only `token_hash` (sha256, not pbkdf2; the token itself is
    high-entropy random, not a human-chosen password, so slow-hashing buys
    nothing and would make every public-API request pay a 200k-iteration
    cost) is stored; the plaintext token is returned exactly once at
    creation time and never again, same "never echo a secret back"
    philosophy as `PlatformConfig`'s `*_set: bool` pattern.
    `token_prefix` (first 12 chars of the plaintext) is stored only so the
    UI can show "which token is this" (e.g. `toleman_pat_a1b2c3...`)
    without ever re-deriving or displaying the full value.

    `scope` is a single flat read/read_write flag, deliberately not a
    granular per-endpoint permission model for this first version, same
    "simple scalar over a rule table until proven necessary" choice made
    for `jira_auto_create_severity` (#74). Read-only is the default; a
    caller must explicitly request read_write at creation time.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    name: str
    token_hash: str = Field(unique=True, index=True)
    token_prefix: str
    scope: ApiTokenScope = ApiTokenScope.READ
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


class CodeGraph(SQLModel, table=True):
    """Persisted import graph for one target (issue #244, Stage 1).

    `edges` maps a repo-relative file path to the list of files that
    directly import it -- the *importer* direction, because that is the
    direction blast radius queries ("this file changed; what else is
    affected?"). The forward edge is its exact inverse and is recoverable by
    transposing, so only one direction is stored.

    One row per target (unique `target_id`); a rebuild replaces it rather
    than accumulating history, since only the current structure can narrow a
    scan. `commit_sha` is what makes the row safe to reuse: it is matched
    **exactly**, never "close enough", because a graph built from a
    different commit describes a different import structure and using it
    would narrow a scan against a tree that no longer exists. That is the
    staleness rule the issue's discussion asked for, resolved by keying on
    the commit rather than on an age window -- app.core.code_graph builds
    from the checkout the scan already has, so a miss costs one rebuild
    rather than a fallback to scanning everything.

    Python-only in this stage. A target whose changed files are TypeScript
    or Go gets no expansion from this table, and the PR comment must not
    describe such a scan as having had its blast radius checked.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", unique=True, index=True)
    commit_sha: str = Field(index=True)
    # {file_path: [files importing it]} -- see app/core/code_graph.py
    edges: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    file_count: int = 0  # Python modules indexed, not edges recorded
    built_at: datetime = Field(default_factory=datetime.utcnow)
