// NEXT_PUBLIC_API_URL is inlined at build time into both the browser bundle
// and server-rendered code, so it must point wherever the *browser* can
// reach the backend (e.g. a published host port). Server Components/route
// handlers instead run inside the frontend container itself, where that
// address usually isn't reachable (e.g. "localhost" resolves to the
// frontend container, not the backend one) -- API_INTERNAL_URL is a plain
// (non-NEXT_PUBLIC_) runtime env var read fresh on the server for exactly
// that case, e.g. set to "http://backend:8000" on the docker-compose
// internal network. It's never bundled for the browser, so this has no
// effect on local `npm run dev` unless explicitly set.
export const API_URL = process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// A group/tag badge embedded on a Target (issue #61) -- e.g. "production",
// "PCI-scope". Also the shape returned standalone by the /api/groups CRUD
// endpoints (which additionally carry workspace_id/created_at, see Group
// below).
export type GroupBadge = { id: number; name: string; color: string };

// PR Guardrail enforcement mode (issue #62): whether a policy-blocking PR
// Guardrail scan actually fails the build ("block"), just warns via a
// non-blocking commit status ("alert"), or PR Guardrail doesn't run at all
// ("disabled"). Settable at Target/Group/Workspace level with
// most-specific-wins inheritance -- null means "inherit", not "alert".
export type EnforcementMode = "block" | "alert" | "disabled";
// Where an *effective* (resolved) enforcement mode came from -- surfaced on
// GET /api/targets/{id} as effective_enforcement_mode/enforcement_mode_source
// so the target detail page can show "Enforcement: Block (inherited from
// workspace)" instead of just a raw settable field.
export type EnforcementModeSource = "target" | "group" | "workspace" | "default";

export type Target = {
  id: number;
  workspace_id: number;
  name: string;
  repo_url: string;
  default_branch: string;
  label: string;
  criticality_weight: number;
  groups: GroupBadge[];
  // Pipeline integration (issue #66): whether a PR adding
  // .github/workflows/osp-scan.yml has been opened against this target's repo.
  pipeline_integrated: boolean;
  pipeline_pr_url: string | null;
  // Issue #62. enforcement_mode is this target's own raw override (null =
  // no override, inherit). effective_enforcement_mode/enforcement_mode_source
  // are only present on GET /api/targets/{id} (single-target detail), not
  // the list endpoint.
  enforcement_mode: EnforcementMode | null;
  effective_enforcement_mode?: EnforcementMode;
  enforcement_mode_source?: EnforcementModeSource;
};

// GET /api/targets/{id}/pipeline-workflow (issue #66) -- generated,
// target-specific GitHub Actions workflow YAML, not yet written to GitHub.
export type PipelineWorkflow = {
  yaml: string;
  path: string;
  includes_gosec: boolean;
  languages: string[];
  detection_source: "scan_history" | "github_languages" | "default";
};

export type PipelineIntegrateResult = {
  pipeline_integrated: boolean;
  pipeline_pr_url: string | null;
  pr_number: number;
  branch: string;
};

// Issue #68: bulk "Add Pipeline" -- multi-select wrapper around #66's
// per-target mechanism above. POST /api/targets/bulk-pipeline-integrate
// dispatches a Celery task (#59-style async job) and returns immediately;
// poll GET /api/targets/bulk-pipeline-integrate/{batch_id} until status
// leaves "running".
export type PipelineBatchItemStatus = "pending" | "running" | "succeeded" | "failed" | "already_integrated";

export type PipelineBatchItem = {
  target_id: number;
  target_name: string | null;
  repo_url: string | null;
  status: PipelineBatchItemStatus;
  error: string;
  pr_url: string | null;
  pr_number: number | null;
  completed_at: string | null;
};

export type PipelineIntegrationBatch = {
  batch_id: number;
  status: RunStatus; // batch itself only ever reaches "running" or "completed" -- per-item outcomes (including failures) live in `items`
  total: number;
  succeeded: number;
  failed: number;
  already_integrated: number;
  started_at: string;
  completed_at: string | null;
  items: PipelineBatchItem[];
};

export type Group = {
  id: number;
  workspace_id: number;
  name: string;
  color: string;
  created_at: string;
  // Issue #62: group-level enforcement-mode override, applied to every
  // target carrying this group (null = no override, inherit from workspace).
  enforcement_mode: EnforcementMode | null;
};

export type Finding = {
  id: number;
  target_id: number;
  tool: string;
  rule_id: string;
  title: string;
  description: string;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  priority_score: number;
  branch: string;
  state: string;
  cve_id: string | null;
  epss_score: number | null;
  kev_listed: boolean;
  first_seen: string;
  last_seen: string;
  // Issue #70: resolved SLA (days-to-fix), computed on read via
  // app.core.sla.compute_sla_status -- sla_days is null when no SlaRule
  // applies to this finding's group(s)/severity or workspace default;
  // sla_violated is only ever true when a real rule applies AND the
  // finding is still open past that window.
  sla_days: number | null;
  sla_violated: boolean;
};

// A single workspace-scoped SLA (days-to-fix) rule, keyed by severity and
// optionally a repo Group (issue #70) -- group_id null means "workspace
// default", applied to targets with no group-specific rule for that
// severity. See app.core.sla.resolve_sla_days for the group ->
// workspace-default -> "no SLA" resolution.
export type SlaRule = {
  id: number;
  workspace_id: number;
  group_id: number | null;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  days_to_fix: number;
  created_at: string;
};

// No-AI enrichment (issue #71) -- real CVE/CWE/CVSS/fix-version data sourced
// from NVD + OSV.dev, cached server-side. Fields are null when not
// applicable (no cve_id on the finding) or when the upstream source had no
// data for this CVE. Distinct from AiStatus/analyzeFinding below -- this
// always works with zero AI provider configured.
export type FindingEnrichment = {
  finding_id: number;
  cve_id: string | null;
  cve_description: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_ids: string[] | null;
  references: string[] | null;
  fix_versions: { package: string | null; ecosystem: string | null; fixed: string }[] | null;
  fetched_at: string | null;
};

export type AiProvider = "anthropic" | "openai_compatible";

export type AiStatus = {
  configured: boolean;
  provider: AiProvider;
};

export type PlatformConfigView = {
  anthropic_api_key_set: boolean;
  ai_provider: AiProvider;
  openai_compatible_base_url: string;
  openai_compatible_api_key_set: boolean;
  openai_compatible_model: string;
  slack_webhook_url_set: boolean;
  jira_url: string;
  jira_api_token_set: boolean;
  jira_project_key: string;
  jira_issue_type: string;
  jira_auto_create_severity: string | null;
};

export type UpdateConfigPayload = {
  ai_provider?: AiProvider;
  anthropic_api_key?: string;
  openai_compatible_base_url?: string;
  openai_compatible_api_key?: string;
  openai_compatible_model?: string;
  slack_webhook_url?: string;
  jira_url?: string;
  jira_api_token?: string;
  jira_project_key?: string;
  jira_issue_type?: string;
  jira_auto_create_severity?: string;
};

export type TestConnectionResult = {
  success: boolean;
  message: string;
};

export function githubBlobUrl(repoUrl: string, branch: string, filePath: string, lineStart?: number | null): string {
  const repoPath = new URL(repoUrl).pathname.replace(/\.git$/, "").replace(/^\//, "");
  const encodedFilePath = filePath.split("/").map(encodeURIComponent).join("/");
  const url = `https://github.com/${repoPath}/blob/${encodeURIComponent(branch)}/${encodedFilePath}`;
  return lineStart ? `${url}#L${lineStart}` : url;
}

export type Summary = { total: number; open: number; mitigated: number };

// Issue #63: composite security health score. Mirrors
// backend/app/core/security_score.py's return shape exactly -- see that
// module's docstring for how each component/weight is computed.
export type SecurityScoreComponent = {
  score: number;
  weight: number;
  [key: string]: unknown;
};

export type SecurityScore = {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F" | null;
  target_count: number;
  weakest_component: "findings" | "sla" | "coverage" | "fp_rate" | "trend" | null;
  components: {
    findings: SecurityScoreComponent & { open_findings: number; weighted_severity_sum: number; avg_weighted_severity_per_target: number };
    sla: SecurityScoreComponent & { with_sla: number; in_violation: number; compliant: number; note: string | null };
    coverage: SecurityScoreComponent & { scanned_targets: number; total_targets: number; window_days: number };
    fp_rate: SecurityScoreComponent & { false_positives: number; total_findings: number; fp_rate: number };
    trend: SecurityScoreComponent & { direction: "improving" | "stable" | "worsening"; current_weighted_sum: number; prior_weighted_sum: number; window_days: number };
  };
};

export type FindingListResult = { items: Finding[]; total: number };

export type FindingsQuery = {
  target_id?: number;
  group_id?: number;
  state?: string;
  severity?: string;
  tool?: string;
  search?: string;
  page?: number;
  page_size?: number;
};

export type AuthUser = { id: number; email: string; name: string; role: string };

// Issue #73: notification preferences. `slack` posts to the single
// platform-wide webhook (#74) -- opting in means being named in that
// message, not a private DM. `email` is a real saveable preference but has
// no delivery yet (no SMTP infra in this codebase) -- see the backend's
// NotificationChannel docstring.
export type NotificationChannel = "email" | "slack";
export type NotificationEventType = "critical_finding" | "kev_cve" | "sla_breach" | "scan_failure";
export type NotificationPreference = { channel: NotificationChannel; event_type: NotificationEventType; enabled: boolean };

export type WorkspaceSummary = {
  id: number;
  name: string;
  organization_id: number;
  // Issue #62: workspace-level enforcement-mode fallback, used when a target
  // and all of its groups have no override configured (null = no override,
  // falls back to the hardcoded "block" default).
  enforcement_mode: EnforcementMode | null;
};

export type WorkspaceRole = "viewer" | "developer" | "security_engineer";

export type WorkspaceMembership = {
  id: number;
  user_id: number;
  user_email: string;
  user_name: string;
  workspace_id: number;
  workspace_name: string;
  role: WorkspaceRole;
};

export type CommitEvent = { sha: string; message: string; author: string; date: string; url: string };
export type PullRequest = {
  number: number;
  title: string;
  author: string;
  state: string;
  created_at: string;
  merged_at: string | null;
  url: string;
  scan_status: string;
};
export type Endpoint = {
  id: number;
  framework: string;
  method: string;
  route: string;
  file: string;
  line: number;
  is_new: boolean;
  first_seen: string;
  last_seen: string;
};
export type SbomComponent = {
  id: number;
  name: string;
  version: string;
  package_type: string;
  purl: string;
  is_new: boolean;
  first_seen: string;
  last_seen: string;
};

// Async job status shared by the Scan/DiscoveryRun/SbomRun tracking rows
// (#59) -- every POST that used to clone+scan synchronously now returns one
// of these immediately, and the frontend polls the matching GET until
// status leaves "running".
export type RunStatus = "running" | "completed" | "failed";

export type ScanRun = {
  scan_id: number;
  target_id: number;
  tool: string;
  branch: string;
  status: RunStatus;
  findings_count: number;
  started_at: string;
  completed_at: string | null;
};

export type DiscoveryRunResult = {
  run_id: number;
  target_id: number;
  status: RunStatus;
  count: number;
  new_count: number;
  error: string;
  started_at: string;
  completed_at: string | null;
  endpoints?: Endpoint[];
};

export type SbomRunResult = {
  run_id: number;
  target_id: number;
  status: RunStatus;
  count: number;
  new_count: number;
  error: string;
  started_at: string;
  completed_at: string | null;
  components?: SbomComponent[];
};
export type OrgSbomComponent = {
  name: string;
  version: string;
  purl: string;
  package_type: string;
  targets: { id: number; name: string }[];
};
export type OrgSbomResult = {
  targets_with_sbom_count: number;
  total_targets_count: number;
  unique_component_count: number;
  components: OrgSbomComponent[];
};
export type AuditEvent = { type: string; timestamp: string; actor: string; summary: string; reason: string };

export type SearchResults = { findings: Finding[]; targets: Target[] };

// #34: a platform may have multiple registered GitHub Apps, each with its
// own set of installations (e.g. a dev App and a prod App, or the same App
// installed on several orgs/accounts).
export type GitHubAppInstalledAccount = { installation_id: number; account_login: string; account_type: string };
export type GitHubAppInstallation = {
  id: number;
  app_id: string;
  app_slug: string;
  html_url: string;
  webhook_secret_set: boolean;
  installations: GitHubAppInstalledAccount[];
};

export type PolicyRuleType = "block_severity" | "suppress_rule" | "suppress_license";
export type PolicyRule = {
  id: number;
  workspace_id: number;
  rule_type: PolicyRuleType;
  value: string;
  reason: string;
  created_by: string;
  created_at: string;
  active: boolean;
};

// Issue #76: a learned false-positive suppression rule -- created
// automatically when a Finding is triaged to "False Positive" (see
// app.core.fp_learning.learn_suppression_rule), consumed at ingestion time
// to auto-suppress matching new Findings anywhere in the workspace
// (cross-repo). file_path_pattern is a filename basename (e.g.
// "settings.py"), or null meaning "any file for this rule_id+tool".
export type FalsePositiveRule = {
  id: number;
  workspace_id: number;
  rule_id: string;
  tool: string;
  file_path_pattern: string | null;
  source_finding_id: number | null;
  created_by: string;
  created_at: string;
  active: boolean;
  match_count: number;
  last_matched_at: string | null;
};
export type FpRuleStats = { active_rules: number; total_matches: number };

// The ephemeral (non-persisted-id) shape returned inline in a scan's
// response body -- distinct from PrGuardrailFinding below, which is the
// persisted row with its own id and ignore-request lifecycle.
export type PrGuardrailFindingSummary = {
  tool: string;
  rule_id: string;
  title: string;
  file_path: string;
  line_start: number | null;
  severity: string;
};
export type PrGuardrailScanResult = {
  pr_scan_id: number;
  status: "passed" | "blocked" | "error";
  new_findings_count: number;
  highest_new_severity: string | null;
  new_findings: PrGuardrailFindingSummary[];
};
export type IgnoreStatus = "none" | "requested" | "approved" | "rejected";
export type PrGuardrailFinding = {
  id: number;
  pr_scan_id: number;
  tool: string;
  rule_id: string;
  title: string;
  file_path: string;
  line_start: number | null;
  severity: string;
  ignore_status: IgnoreStatus;
  ignore_requested_by: string;
  ignore_requested_reason: string;
  ignore_reviewed_by: string;
  ignore_reviewed_at: string | null;
};
export type PrGuardrailLogEntry = {
  id: number;
  pr_number: number;
  pr_title: string;
  branch: string;
  status: "running" | "passed" | "blocked" | "error" | "overridden";
  new_findings_count: number;
  highest_new_severity: string | null;
  new_endpoints_count: number;
  override_reason: string;
  created_at: string;
  completed_at: string | null;
  // Deep link back to the originating GitHub PR (issue #65), constructed
  // server-side from the target's repo_url + pr_number. Null if the repo
  // URL can't be parsed.
  pr_url: string | null;
  // Present only on org-wide log rows (issue #64) -- a single-target log
  // doesn't need these since the picker already implies the target.
  target_id?: number;
  target_name?: string | null;
};
export type PrGuardrailOrgStats = {
  total: number;
  passed: number;
  blocked: number;
  overridden: number;
  error: number;
  running: number;
};
export type PrGuardrailOrgLog = {
  scans: PrGuardrailLogEntry[];
  stats: PrGuardrailOrgStats;
};

// Configurable dashboard (issue #69): a small, concrete widget catalog
// (KPI cards, findings trend, CVE timeline, SLA compliance, top risky
// repos, recent findings, security score) rather than a generic
// chart-config system -- each widget's real data comes from
// GET /api/dashboard/widget-data, batched for every widget currently in
// the caller's layout. "security_score" (#63) was added after #69 shipped.
export type WidgetId =
  | "kpi_cards"
  | "findings_trend"
  | "cve_timeline"
  | "sla_compliance"
  | "top_risky_repos"
  | "recent_findings"
  | "security_score"
  | "fp_auto_suppressions";

export type WidgetCatalogEntry = { widget_id: WidgetId; name: string; description: string };

export type LayoutWidget = { id: string; widget_id: WidgetId; config: Record<string, unknown> };
export type DashboardLayoutOut = { widgets: LayoutWidget[] };

export type KpiCardsData = { open: number; critical: number; high: number; mitigated: number; targets: number };
export type FindingsTrendData = { points: { date: string; open: number }[] };
export type CveTimelineItem = {
  finding_id: number;
  cve_id: string;
  title: string;
  severity: string;
  state: string;
  target_id: number;
  target_name: string | null;
  first_seen: string;
  epss_score: number | null;
  kev_listed: boolean;
};
export type CveTimelineData = { items: CveTimelineItem[] };
export type SlaComplianceData = { with_sla: number; in_violation: number; compliant: number };
export type TopRiskyRepoItem = {
  target_id: number;
  target_name: string;
  critical: number;
  high: number;
  priority_score_sum: number;
};
export type TopRiskyReposData = { items: TopRiskyRepoItem[] };
export type RecentFindingItem = {
  finding_id: number;
  title: string;
  severity: string;
  state: string;
  tool: string;
  target_id: number;
  target_name: string | null;
  first_seen: string;
  sla_days: number | null;
  sla_violated: boolean;
};
export type RecentFindingsData = { items: RecentFindingItem[] };
// Issue #76: "X findings auto-suppressed this month" widget data.
export type FpAutoSuppressionsData = { count: number; since: string };

export type WidgetDataMap = {
  kpi_cards: KpiCardsData;
  findings_trend: FindingsTrendData;
  cve_timeline: CveTimelineData;
  sla_compliance: SlaComplianceData;
  top_risky_repos: TopRiskyReposData;
  recent_findings: RecentFindingsData;
  security_score: SecurityScore;
  fp_auto_suppressions: FpAutoSuppressionsData;
};

export type WidgetDataEntry =
  | { widget_id: WidgetId; data: WidgetDataMap[WidgetId]; error?: undefined }
  | { widget_id: WidgetId; data?: undefined; error: string };

export type WidgetDataResponse = { widgets: Record<string, WidgetDataEntry> };

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init?.headers as Record<string, string> | undefined) };

  // Server Components/route handlers run on the Node server, not in the
  // browser — `credentials: "include"` is a no-op there since there's no
  // browser cookie jar to draw from. Without forwarding the incoming
  // request's session cookie explicitly, every server-side call 401s and
  // gets silently swallowed by callers' .catch(() => []), which is exactly
  // what made every server-rendered page look like "no data" once the
  // backend started requiring auth (Sprint 1). Dynamic import so this
  // server-only module is never pulled into the client bundle.
  if (typeof window === "undefined") {
    const { cookies } = await import("next/headers");
    const cookieStore = await cookies();
    const session = cookieStore.get("osp_session");
    if (session) {
      headers["Cookie"] = `osp_session=${session.value}`;
    }
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "include",
    headers,
  });
  if (!res.ok) {
    // Surface FastAPI's real {"detail": "..."} error body when present (e.g.
    // the real Slack/Jira error text from test-connection) rather than just
    // the status code.
    let detail: string | undefined;
    try {
      const body = await res.json();
      if (body && typeof body.detail === "string") detail = body.detail;
    } catch {
      // response body wasn't JSON -- fall through to the generic message
    }
    throw new Error(detail || `API ${path} failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    jsonFetch<AuthUser>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => jsonFetch<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  me: () => jsonFetch<AuthUser>("/api/auth/me"),
  updateMe: (name: string) =>
    jsonFetch<AuthUser>("/api/auth/me", { method: "PATCH", body: JSON.stringify({ name }) }),
  changePassword: (currentPassword: string, newPassword: string) =>
    jsonFetch<{ ok: boolean }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  notificationPreferences: () => jsonFetch<NotificationPreference[]>("/api/notification-preferences"),
  setNotificationPreferences: (preferences: NotificationPreference[]) =>
    jsonFetch<NotificationPreference[]>("/api/notification-preferences", {
      method: "PUT",
      body: JSON.stringify({ preferences }),
    }),
  targets: (query: { group_id?: number } = {}) => {
    const params = new URLSearchParams();
    if (query.group_id) params.set("group_id", String(query.group_id));
    const qs = params.toString();
    return jsonFetch<Target[]>(`/api/targets${qs ? `?${qs}` : ""}`);
  },
  target: (id: number) => jsonFetch<Target>(`/api/targets/${id}`),
  createTarget: (t: Partial<Target>) =>
    jsonFetch<Target>("/api/targets", { method: "POST", body: JSON.stringify(t) }),
  findings: (query: FindingsQuery = {}) => {
    const params = new URLSearchParams();
    if (query.target_id) params.set("target_id", String(query.target_id));
    if (query.group_id) params.set("group_id", String(query.group_id));
    if (query.state) params.set("state", query.state);
    if (query.severity) params.set("severity", query.severity);
    if (query.tool) params.set("tool", query.tool);
    if (query.search) params.set("search", query.search);
    if (query.page) params.set("page", String(query.page));
    if (query.page_size) params.set("page_size", String(query.page_size));
    return jsonFetch<FindingListResult>(`/api/findings?${params.toString()}`);
  },
  // Issue #61: workspace-scoped Group CRUD + Target<->Group assignment.
  groups: (workspaceId?: number) =>
    jsonFetch<Group[]>(`/api/groups${workspaceId ? `?workspace_id=${workspaceId}` : ""}`),
  createGroup: (g: { workspace_id: number; name: string; color?: string }) =>
    jsonFetch<Group>("/api/groups", { method: "POST", body: JSON.stringify(g) }),
  updateGroup: (id: number, patch: { name?: string; color?: string; enforcement_mode?: EnforcementMode | null }) =>
    jsonFetch<Group>(`/api/groups/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteGroup: (id: number) => jsonFetch<{ ok: boolean }>(`/api/groups/${id}`, { method: "DELETE" }),
  // Issue #70: workspace-scoped SlaRule CRUD (SECURITY_ENGINEER-or-admin
  // gated on the backend).
  slaRules: (workspaceId?: number) =>
    jsonFetch<SlaRule[]>(`/api/sla-rules${workspaceId ? `?workspace_id=${workspaceId}` : ""}`),
  createSlaRule: (r: { workspace_id: number; group_id: number | null; severity: string; days_to_fix: number }) =>
    jsonFetch<SlaRule>("/api/sla-rules", { method: "POST", body: JSON.stringify(r) }),
  updateSlaRule: (id: number, patch: { days_to_fix: number }) =>
    jsonFetch<SlaRule>(`/api/sla-rules/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteSlaRule: (id: number) => jsonFetch<{ ok: boolean }>(`/api/sla-rules/${id}`, { method: "DELETE" }),
  slaCompliance: () =>
    jsonFetch<{ with_sla: number; in_violation: number; compliant: number }>("/api/dashboard/sla-compliance"),
  // Issue #63: composite 0-100 security health score + letter grade +
  // per-component breakdown. Org-wide with no args; pass exactly one of
  // targetId/groupId to scope (mutually exclusive, enforced server-side).
  // Also backs the "Security Score" dashboard widget (#69's widget system)
  // for its org-wide default view -- this function is what the widget's own
  // scope selector calls for a scoped (group/target) drill-down, since
  // there's no per-widget-instance config editor in this dashboard yet.
  securityScore: (scope: { targetId?: number; groupId?: number } = {}) => {
    const params = new URLSearchParams();
    if (scope.targetId) params.set("target_id", String(scope.targetId));
    if (scope.groupId) params.set("group_id", String(scope.groupId));
    const qs = params.toString();
    return jsonFetch<SecurityScore>(`/api/dashboard/security-score${qs ? `?${qs}` : ""}`);
  },
  targetGroups: (targetId: number) => jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups`),
  assignTargetGroup: (targetId: number, groupId: number) =>
    jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups/${groupId}`, { method: "POST" }),
  removeTargetGroup: (targetId: number, groupId: number) =>
    jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups/${groupId}`, { method: "DELETE" }),
  triage: (findingId: number, toState: string, reason: string) =>
    jsonFetch<Finding>(
      `/api/findings/${findingId}/triage?to_state=${encodeURIComponent(toState)}&reason=${encodeURIComponent(reason)}`,
      { method: "POST" }
    ),
  bulkTriage: (findingIds: number[], toState: string, reason: string) =>
    jsonFetch<{ updated: number; items: Finding[] }>("/api/findings/bulk-triage", {
      method: "POST",
      body: JSON.stringify({ finding_ids: findingIds, to_state: toState, reason }),
    }),
  findingTools: () => jsonFetch<string[]>("/api/findings/facets/tools"),
  summary: () => jsonFetch<Summary>("/api/dashboard/summary"),
  stats: () =>
    jsonFetch<{ open: number; by_severity: Record<string, number>; by_tool: Record<string, number> }>(
      "/api/dashboard/stats"
    ),
  // Issue #69: configurable dashboard -- widget catalog, per-user saved
  // layout (add/remove/reorder), and one batched call for every widget's
  // real data.
  dashboardWidgets: () => jsonFetch<WidgetCatalogEntry[]>("/api/dashboard/widgets"),
  dashboardLayout: () => jsonFetch<DashboardLayoutOut>("/api/dashboard/layout"),
  saveDashboardLayout: (widgets: LayoutWidget[]) =>
    jsonFetch<DashboardLayoutOut>("/api/dashboard/layout", { method: "PUT", body: JSON.stringify({ widgets }) }),
  dashboardWidgetData: () => jsonFetch<WidgetDataResponse>("/api/dashboard/widget-data"),
  posture: () => jsonFetch<{ target: Target; breakdown: Record<string, Record<string, number>> }[]>(
    "/api/dashboard/posture"
  ),
  // Dispatches a Celery task and returns immediately with status: "running"
  // (#59) -- callers must poll api.getScan(scan_id) until status leaves
  // "running". target-not-found/unsupported-tool are still synchronous
  // 200 { error } responses (validated before dispatch).
  runScan: (targetId: number, tool: string) =>
    jsonFetch<{ scan_id: number; status: RunStatus } | { error: string }>(
      `/api/scans/run?target_id=${targetId}&tool=${tool}`,
      { method: "POST" }
    ),
  getScan: (scanId: number) => jsonFetch<ScanRun | { error: string }>(`/api/scans/${scanId}`),
  updateTarget: (id: number, patch: Partial<Target>) =>
    jsonFetch<Target>(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  workspaceKey: (targetId: number) =>
    jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(`/api/targets/${targetId}/workspace-key`),
  // Issue #66: generate/inspect the per-target CI/CD scan workflow, and open
  // a real PR against the target's GitHub repo adding it.
  pipelineWorkflow: (targetId: number) =>
    jsonFetch<PipelineWorkflow>(`/api/targets/${targetId}/pipeline-workflow`),
  integratePipeline: (targetId: number) =>
    jsonFetch<PipelineIntegrateResult | { error: string }>(`/api/targets/${targetId}/pipeline-integrate`, {
      method: "POST",
    }),
  // Issue #68: multi-select "Add Pipeline" -- dispatches a Celery batch and
  // returns immediately (#59-style async job); poll
  // getPipelineIntegrationBatch(batch_id) until status leaves "running".
  bulkPipelineIntegrate: (targetIds: number[]) =>
    jsonFetch<{ batch_id: number; total: number; status: RunStatus }>("/api/targets/bulk-pipeline-integrate", {
      method: "POST",
      body: JSON.stringify({ target_ids: targetIds }),
    }),
  getPipelineIntegrationBatch: (batchId: number) =>
    jsonFetch<PipelineIntegrationBatch>(`/api/targets/bulk-pipeline-integrate/${batchId}`),
  activity: (targetId: number) => jsonFetch<CommitEvent[]>(`/api/github/activity/${targetId}`),
  orgActivity: () => jsonFetch<(CommitEvent & { target: string })[]>("/api/github/org-activity"),
  prs: (targetId: number) => jsonFetch<PullRequest[]>(`/api/github/prs/${targetId}`),
  getDiscoveredEndpoints: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; endpoints: Endpoint[] }>(`/api/discovery/${targetId}`),
  // Dispatches a Celery task and returns immediately with run_id/status:
  // "running" (#59) -- poll api.getDiscoveryRun(targetId, run_id) until
  // status leaves "running".
  runDiscovery: (targetId: number) =>
    jsonFetch<{ run_id: number; target_id: number; status: RunStatus }>(`/api/discovery/${targetId}`, {
      method: "POST",
    }),
  getDiscoveryRun: (targetId: number, runId: number) =>
    jsonFetch<DiscoveryRunResult>(`/api/discovery/${targetId}/runs/${runId}`),
  getSbom: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; components: SbomComponent[] }>(`/api/sbom/${targetId}`),
  // Dispatches a Celery task and returns immediately with run_id/status:
  // "running" (#59) -- poll api.getSbomRun(targetId, run_id) until status
  // leaves "running".
  generateSbom: (targetId: number) =>
    jsonFetch<{ run_id: number; target_id: number; status: RunStatus }>(`/api/sbom/${targetId}`, {
      method: "POST",
    }),
  getSbomRun: (targetId: number, runId: number) => jsonFetch<SbomRunResult>(`/api/sbom/${targetId}/runs/${runId}`),
  exportSbom: async (targetId: number): Promise<Blob> => {
    const res = await fetch(`${API_URL}/api/sbom/${targetId}/export`, { credentials: "include" });
    if (!res.ok) throw new Error(`export failed: ${res.status}`);
    return res.blob();
  },
  getOrgSbom: () => jsonFetch<OrgSbomResult>("/api/sbom/org"),
  exportOrgSbom: async (): Promise<Blob> => {
    const res = await fetch(`${API_URL}/api/sbom/org/export`, { credentials: "include" });
    if (!res.ok) throw new Error(`export failed: ${res.status}`);
    return res.blob();
  },
  exportPostureReport: async (
    targetId: number | null,
    format: "csv" | "pdf",
  ): Promise<Blob> => {
    const params = new URLSearchParams({ format });
    // Target ids are positive (DB serial starting at 1); 0 is the shared
    // "All repositories" sentinel from components/target-picker.tsx's
    // ALL_TARGETS -- omitting target_id entirely is how the backend knows
    // to build the org-wide report.
    if (targetId !== null && targetId !== 0) {
      params.set("target_id", String(targetId));
    }
    const res = await fetch(`${API_URL}/api/reports/posture?${params.toString()}`, {
      credentials: "include",
    });
    if (!res.ok) throw new Error(`report export failed: ${res.status}`);
    return res.blob();
  },
  findingEnrichment: (findingId: number) => jsonFetch<FindingEnrichment>(`/api/findings/${findingId}/enrichment`),
  aiStatus: () => jsonFetch<AiStatus>("/api/ai/status"),
  analyzeFinding: (findingId: number) =>
    jsonFetch<{ finding_id: number; analysis: string }>(`/api/ai/analyze/${findingId}`, { method: "POST" }),
  auditLog: () => jsonFetch<AuditEvent[]>("/api/audit/log"),
  users: () => jsonFetch<AuthUser[]>("/api/admin/users"),
  createUser: (u: { email: string; name: string; password: string; role: string }) =>
    jsonFetch<AuthUser>("/api/admin/users", { method: "POST", body: JSON.stringify(u) }),
  updateUserRole: (id: number, role: string) =>
    jsonFetch<AuthUser>(`/api/admin/users/${id}/role`, { method: "PATCH", body: JSON.stringify({ role }) }),
  deleteUser: (id: number) => jsonFetch<{ ok: boolean }>(`/api/admin/users/${id}`, { method: "DELETE" }),
  workspaces: () => jsonFetch<WorkspaceSummary[]>("/api/workspaces"),
  // Issue #62: workspace-level enforcement-mode fallback setting.
  updateWorkspace: (id: number, patch: { enforcement_mode?: EnforcementMode | null }) =>
    jsonFetch<WorkspaceSummary>(`/api/workspaces/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  workspaceMemberships: (workspaceId?: number) =>
    jsonFetch<WorkspaceMembership[]>(`/api/admin/workspace-roles${workspaceId ? `?workspace_id=${workspaceId}` : ""}`),
  assignWorkspaceRole: (userId: number, workspaceId: number, role: WorkspaceRole) =>
    jsonFetch<WorkspaceMembership>("/api/admin/workspace-roles", {
      method: "PUT",
      body: JSON.stringify({ user_id: userId, workspace_id: workspaceId, role }),
    }),
  removeWorkspaceMembership: (membershipId: number) =>
    jsonFetch<{ ok: boolean }>(`/api/admin/workspace-roles/${membershipId}`, { method: "DELETE" }),
  githubAppStatus: () =>
    jsonFetch<{
      apps: GitHubAppInstallation[];
      app_configured: boolean;
      app_slug: string | null;
      installed: boolean;
      account_login: string | null;
      webhook_secret_set: boolean;
    }>("/api/github-app/status"),
  githubAppManifestData: (org?: string) =>
    jsonFetch<{ manifest: object; post_url: string }>(`/api/github-app/manifest-data${org ? `?org=${encodeURIComponent(org)}` : ""}`),
  githubAppSync: () => jsonFetch<{ created: number }>("/api/github-app/sync", { method: "POST" }),
  updateWebhookSecret: (webhook_secret: string, config_id?: number) =>
    jsonFetch<{ webhook_secret_set: boolean }>("/api/github-app/webhook-secret", {
      method: "PATCH",
      body: JSON.stringify({ webhook_secret, config_id }),
    }),
  getConfig: () => jsonFetch<PlatformConfigView>("/api/config"),
  updateConfig: (payload: UpdateConfigPayload) =>
    jsonFetch<PlatformConfigView>("/api/config", { method: "POST", body: JSON.stringify(payload) }),
  testSlack: (webhookUrl?: string) =>
    jsonFetch<TestConnectionResult>("/api/config/test-slack", {
      method: "POST",
      body: JSON.stringify({ webhook_url: webhookUrl || undefined }),
    }),
  testJira: (jiraUrl?: string, apiToken?: string) =>
    jsonFetch<TestConnectionResult>("/api/config/test-jira", {
      method: "POST",
      body: JSON.stringify({ jira_url: jiraUrl || undefined, jira_api_token: apiToken || undefined }),
    }),
  toolsHealth: () =>
    jsonFetch<{ tool: string; installed: boolean; version: string | null; response_ms: number | null }[]>(
      "/api/tools/health"
    ),
  runPrGuardrailScan: (targetId: number, prNumber: number) =>
    jsonFetch<PrGuardrailScanResult>(
      `/api/pr-guardrail/scan?target_id=${targetId}&pr_number=${prNumber}`,
      { method: "POST" }
    ),
  getPrGuardrailLog: (targetId: number) =>
    jsonFetch<PrGuardrailLogEntry[]>(`/api/pr-guardrail/log?target_id=${targetId}`),
  getPrGuardrailOrgLog: () => jsonFetch<PrGuardrailOrgLog>("/api/pr-guardrail/log"),
  overridePrGuardrail: (prScanId: number, reason: string) =>
    jsonFetch<PrGuardrailLogEntry>(`/api/pr-guardrail/${prScanId}/override`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  getPrGuardrailFindings: (prScanId: number) =>
    jsonFetch<PrGuardrailFinding[]>(`/api/pr-guardrail/${prScanId}/findings`),
  requestIgnoreFinding: (findingId: number, reason: string) =>
    jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/request-ignore`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  getPendingIgnoreRequests: () =>
    jsonFetch<PrGuardrailFinding[]>("/api/pr-guardrail/ignore-requests/pending"),
  approveIgnore: (findingId: number) =>
    jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/approve-ignore`, { method: "POST" }),
  rejectIgnore: (findingId: number) =>
    jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/reject-ignore`, { method: "POST" }),
  search: (q: string) => jsonFetch<SearchResults>(`/api/search?q=${encodeURIComponent(q)}`),
  listPolicies: (workspaceId: number) => jsonFetch<PolicyRule[]>(`/api/policies?workspace_id=${workspaceId}`),
  createPolicy: (p: { workspace_id: number; rule_type: PolicyRuleType; value: string; reason?: string }) =>
    jsonFetch<PolicyRule>("/api/policies", { method: "POST", body: JSON.stringify(p) }),
  deletePolicy: (id: number) => jsonFetch<PolicyRule>(`/api/policies/${id}`, { method: "DELETE" }),
  // Issue #76: false-positive learning engine -- rules are learned
  // automatically from triage, this is view/expire/revoke only (see
  // app/api/fp_rules.py's module docstring for why there's no manual POST).
  fpRules: (workspaceId?: number) =>
    jsonFetch<FalsePositiveRule[]>(`/api/fp-rules${workspaceId ? `?workspace_id=${workspaceId}` : ""}`),
  fpRuleStats: (workspaceId?: number) =>
    jsonFetch<FpRuleStats>(`/api/fp-rules/stats${workspaceId ? `?workspace_id=${workspaceId}` : ""}`),
  setFpRuleActive: (id: number, active: boolean) =>
    jsonFetch<FalsePositiveRule>(`/api/fp-rules/${id}`, { method: "PATCH", body: JSON.stringify({ active }) }),
  widenFpRule: (id: number) =>
    jsonFetch<FalsePositiveRule>(`/api/fp-rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ clear_file_path_pattern: true }),
    }),
  deleteFpRule: (id: number) => jsonFetch<{ ok: boolean }>(`/api/fp-rules/${id}`, { method: "DELETE" }),
};
