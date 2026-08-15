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
  // .github/workflows/rikugan-scan.yml has been opened against this target's repo.
  pipeline_integrated: boolean;
  pipeline_pr_url: string | null;
  // Issue #62. enforcement_mode is this target's own raw override (null =
  // no override, inherit). effective_enforcement_mode/enforcement_mode_source
  // are only present on GET /api/targets/{id} (single-target detail), not
  // the list endpoint.
  enforcement_mode: EnforcementMode | null;
  effective_enforcement_mode?: EnforcementMode;
  enforcement_mode_source?: EnforcementModeSource;
  // Issue #72: live base URL of this target's deployed API. Active API
  // scanning refuses to run until this is set -- see api.runApiScan.
  api_base_url: string | null;
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
  // Issue #35: "" for #68's original manual-selection batches; a
  // human-readable description of the resolved scope (e.g. "Workspace:
  // acme-prod") for a mass rollout batch. workflow_template_id is set when
  // that rollout used a Custom Workflow Builder template instead of the
  // default scanner set.
  scope_label?: string;
  workflow_template_id?: number | null;
};

// Custom Workflow Builder (issue #35): the fixed catalog of scanners a
// PipelineWorkflowTemplate's step list may reference -- kept in sync with
// backend/app/core/pipeline_workflow.py's SUPPORTED_TOOLS.
export const PIPELINE_WORKFLOW_TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"] as const;
export type PipelineWorkflowTool = (typeof PIPELINE_WORKFLOW_TOOLS)[number];

export type PipelineWorkflowStep = {
  tool: PipelineWorkflowTool;
  enabled: boolean;
};

export type PipelineWorkflowTemplate = {
  id: number;
  workspace_id: number;
  name: string;
  steps: PipelineWorkflowStep[];
  created_by_user_id: number;
  created_at: string;
  updated_at: string;
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

// Issue #75: one entry from GET /api/tools/registry -- every OSS scanner
// Rikugan knows about (app.core.tool_registry.TOOL_REGISTRY), merged with a
// real live health check the same way the original 4-tool /health always
// worked. `integrated` is false for a registry-only tool (e.g. kics) with
// no real TOOL_COMMANDS entry -- Rikugan can show it and check for the binary,
// but can't actually dispatch a scan for it yet.
export type ToolRegistryEntry = {
  tool: string;
  display_name: string;
  category: string;
  languages: string[];
  description: string;
  install_cmd: string;
  docs_url: string;
  integrated: boolean;
  installed: boolean;
  version: string | null;
  response_ms: number | null;
};

// Issue #75: per-workspace usage assignment for one tool. `is_default` is
// true when there's no saved WorkspaceToolConfig row yet and the platform's
// built-in default is being shown instead of an explicit choice.
export type ToolAssignment = {
  tool: string;
  on_demand_scan: boolean;
  ci_pipeline: boolean;
  api_scan: boolean;
  pr_guardrail: boolean;
  is_default: boolean;
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

// Issue #122: one entry from GET /api/ai/recent -- a finding this user has
// previously run AI analysis on, most-recently-analyzed first. Backed by
// AiAnalysisRun (one row per user+finding, upserted on repeat analysis),
// not a full analysis-history log -- there's no stored analysis text here,
// just enough to re-open the finding and re-run analysis.
export type AiRecentAnalysis = {
  finding_id: number;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  cve_id: string | null;
  target_id: number;
  target_name: string;
  state: string;
  last_analyzed_at: string;
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
  siem_webhook_url_set: boolean;
  siem_export_severity: string | null;
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
  siem_webhook_url?: string;
  siem_export_severity?: string;
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

// Issue #109: public API personal access tokens.
export type ApiTokenScope = "read" | "read_write";
export type ApiToken = {
  id: number;
  name: string;
  token_prefix: string;
  scope: ApiTokenScope;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

export type WorkspaceSummary = {
  id: number;
  name: string;
  organization_id: number;
  // Issue #62: workspace-level enforcement-mode fallback, used when a target
  // and all of its groups have no override configured (null = no override,
  // falls back to the hardcoded "block" default).
  enforcement_mode: EnforcementMode | null;
};

// Issue #118: real seeded data has multiple workspaces named "default"
// (e.g. ids 1 and 7, each in a different organization) that are otherwise
// indistinguishable in every workspace picker across the admin tabs. Append
// a disambiguator only when a name collides within the given list, so a
// single-workspace org's clean "acme-corp" label stays untouched. Used by
// every admin-tab workspace `<select>` (workspace-roles, groups, sla-rules,
// workflow-templates, fp-rules, policies).
export function workspaceDisplayName(
  workspace: Pick<WorkspaceSummary, "id" | "name">,
  allWorkspaces: Pick<WorkspaceSummary, "id" | "name">[]
): string {
  const isDuplicate = allWorkspaces.filter((w) => w.name === workspace.name).length > 1;
  return isDuplicate ? `${workspace.name} (#${workspace.id})` : workspace.name;
}

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

export type OrgActivityEvent = CommitEvent & { target: string; target_id: number };
export type OrgActivityQuery = { target_id?: number; date_from?: string; date_to?: string; page?: number; page_size?: number };
export type OrgActivityResult = { items: OrgActivityEvent[]; total: number };
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

// Issue #121: export-format parity with Reports (CSV/PDF) plus the two real
// SBOM standards -- CycloneDX was already produced (`trivy fs --format
// cyclonedx`); SPDX JSON is the other one compliance tooling commonly
// expects. Matches GET /api/sbom/{id}/export's `format` query pattern.
export type SbomExportFormat = "cyclonedx-json" | "spdx-json" | "csv" | "pdf";

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
  // (#153) failure reason -- set on real clone/tool errors and on the
  // lazy stale-job timeout (app/core/staleness.py); "" while running/completed.
  // Deliberately not named `error` -- the sibling { error: string } shape
  // (scan/target not found) is used as a discriminator via `"error" in scan`
  // elsewhere, and this field must not collide with that check.
  error_message: string;
};

// GET /api/scans/summary (#120): per-target scan history so the Scans page
// can show a real "last scanned Xd ago · tool, tool" line and support a
// last-scanned filter, instead of the old flat grid which had no scan
// history surfaced at all. Keyed by target id (as a string -- JSON object
// keys).
export type ScanSummaryEntry = {
  last_scan_at: string | null;
  tools: string[];
};
export type ScanSummary = Record<string, ScanSummaryEntry>;

// Issue #174: per-target open-finding counts for the Repo Sync inventory,
// keyed by target id (string) exactly like ScanSummary above so both index
// the same way. Default-branch + open-state scoped server-side, matching the
// Posture dashboard and the security score.
export type TargetSummaryEntry = {
  open: number;
  critical: number;
  high: number;
};
export type TargetSummary = Record<string, TargetSummaryEntry>;

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
export type AuditEventExpandItem = { finding_id: number; title: string | null; from_state: string; to_state: string; timestamp: string };
export type AuditEvent = {
  type: string;
  timestamp: string;
  actor: string;
  summary: string;
  reason: string;
  grouped_count: number;
  expand: AuditEventExpandItem[] | null;
};
export type AuditLogQuery = {
  event_type?: string;
  actor?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  page_size?: number;
};
export type AuditLogResult = { items: AuditEvent[]; total: number };

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
  // Issue #119: distinguishes rows that share title/target/tool/date (e.g.
  // the same rule firing across several files in one scan) so they don't
  // render as visually-identical duplicates.
  file_path: string;
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

// Carries the real HTTP status alongside the message (issue #121) -- callers
// that need to distinguish "session expired/revoked" (401) from any other
// failure (e.g. PR History's error state) previously only had the message
// string to go on. Still `instanceof Error` for every existing
// `e instanceof Error ? e.message : "..."` catch-block across the app.
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

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
    const session = cookieStore.get("rikugan_session");
    if (session) {
      headers["Cookie"] = `rikugan_session=${session.value}`;
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
    throw new ApiError(detail || `API ${path} failed: ${res.status}`, res.status);
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
  scanSummary: () => jsonFetch<ScanSummary>("/api/scans/summary"),
  targetsSummary: () => jsonFetch<TargetSummary>("/api/targets/summary"),
  updateTarget: (id: number, patch: Partial<Target>) =>
    jsonFetch<Target>(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  workspaceKey: (targetId: number) =>
    jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(`/api/targets/${targetId}/workspace-key`),
  // Issue #129: rotate the workspace's CI-push-ingestion API key. The old
  // key stops authenticating against /api/ingest immediately (no grace
  // period) once this resolves.
  regenerateWorkspaceKey: (targetId: number) =>
    jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(
      `/api/targets/${targetId}/workspace-key/regenerate`,
      { method: "POST" }
    ),
  // Issue #109: personal access tokens for the public API
  // (/api/public/v1/*, Bearer-token auth) -- distinct from the workspace
  // API key above, which is CI-ingest-only and shared workspace-wide.
  apiTokens: () => jsonFetch<ApiToken[]>("/api/api-tokens"),
  createApiToken: (name: string, scope: ApiTokenScope) =>
    jsonFetch<ApiToken & { token: string }>("/api/api-tokens", {
      method: "POST",
      body: JSON.stringify({ name, scope }),
    }),
  revokeApiToken: (id: number) => jsonFetch<ApiToken>(`/api/api-tokens/${id}/revoke`, { method: "POST" }),
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
  // Issue #35 (Mass CI/CD Rollout Engine): scope-based sibling to
  // bulkPipelineIntegrate above -- resolves an entire workspace/group/"all
  // accessible" scope into a target set server-side instead of an explicit
  // target_ids list, reusing the exact same batch tracking + polling
  // (getPipelineIntegrationBatch above works for both).
  massPipelineRollout: (payload: {
    scope: "workspace" | "group" | "all";
    workspace_id?: number;
    group_id?: number;
    workflow_template_id?: number;
  }) =>
    jsonFetch<{ batch_id: number; total: number; status: RunStatus; scope_label: string }>(
      "/api/targets/mass-pipeline-rollout",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  // Custom Workflow Builder (issue #35): workspace-scoped
  // PipelineWorkflowTemplate CRUD, consumed by massPipelineRollout above
  // (and reusable later from the single-target integrate flow).
  pipelineTemplates: (workspaceId?: number) =>
    jsonFetch<PipelineWorkflowTemplate[]>(
      `/api/pipeline-templates${workspaceId ? `?workspace_id=${workspaceId}` : ""}`
    ),
  createPipelineTemplate: (t: { workspace_id: number; name: string; steps: PipelineWorkflowStep[] }) =>
    jsonFetch<PipelineWorkflowTemplate>("/api/pipeline-templates", { method: "POST", body: JSON.stringify(t) }),
  updatePipelineTemplate: (id: number, patch: { name?: string; steps?: PipelineWorkflowStep[] }) =>
    jsonFetch<PipelineWorkflowTemplate>(`/api/pipeline-templates/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deletePipelineTemplate: (id: number) =>
    jsonFetch<{ deleted: boolean }>(`/api/pipeline-templates/${id}`, { method: "DELETE" }),
  activity: (targetId: number) => jsonFetch<CommitEvent[]>(`/api/github/activity/${targetId}`),
  orgActivity: (query: OrgActivityQuery = {}) => {
    const params = new URLSearchParams();
    if (query.target_id) params.set("target_id", String(query.target_id));
    if (query.date_from) params.set("date_from", query.date_from);
    if (query.date_to) params.set("date_to", query.date_to);
    if (query.page) params.set("page", String(query.page));
    if (query.page_size) params.set("page_size", String(query.page_size));
    return jsonFetch<OrgActivityResult>(`/api/github/org-activity?${params.toString()}`);
  },
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
  // Issue #72: active API scanning (nuclei) against endpoints already
  // discovered above. Same dispatch-then-poll shape as runScan -- 202 with
  // scan_id immediately, poll api.getScan(scan_id) until status leaves
  // "running". endpointIds narrows to a specific selection; omit to scan
  // every discovered endpoint for the target's default branch. A 400 means
  // the target has no api_base_url configured yet or nothing is scannable.
  runApiScan: (targetId: number, endpointIds?: number[]) =>
    jsonFetch<{ scan_id: number; target_id: number; status: RunStatus; endpoint_count: number }>(
      `/api/api-scan/${targetId}`,
      { method: "POST", body: JSON.stringify({ endpoint_ids: endpointIds ?? null }) }
    ),
  getLatestApiScan: (targetId: number) =>
    jsonFetch<{ target_id: number; scan: ScanRun | null }>(`/api/api-scan/${targetId}/latest`),
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
  exportSbom: async (targetId: number, format: SbomExportFormat = "cyclonedx-json"): Promise<Blob> => {
    const res = await fetch(`${API_URL}/api/sbom/${targetId}/export?format=${format}`, { credentials: "include" });
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
  aiRecentAnalyses: () => jsonFetch<AiRecentAnalysis[]>("/api/ai/recent"),
  auditLog: (query: AuditLogQuery = {}) => {
    const params = new URLSearchParams();
    if (query.event_type) params.set("event_type", query.event_type);
    if (query.actor) params.set("actor", query.actor);
    if (query.date_from) params.set("date_from", query.date_from);
    if (query.date_to) params.set("date_to", query.date_to);
    if (query.page) params.set("page", String(query.page));
    if (query.page_size) params.set("page_size", String(query.page_size));
    return jsonFetch<AuditLogResult>(`/api/audit/log?${params.toString()}`);
  },
  auditActors: () => jsonFetch<string[]>("/api/audit/actors"),
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
  testSiem: (webhookUrl?: string) =>
    jsonFetch<TestConnectionResult>("/api/config/test-siem", {
      method: "POST",
      body: JSON.stringify({ webhook_url: webhookUrl || undefined }),
    }),
  toolsHealth: () =>
    jsonFetch<{ tool: string; installed: boolean; version: string | null; response_ms: number | null }[]>(
      "/api/tools/health"
    ),
  // Issue #75: tool marketplace registry (every supported OSS scanner,
  // SAST/SCA/Secrets/Container/IaC/License, real live health check merged
  // in) and per-workspace usage assignment (which of on-demand/CI
  // pipeline/API scan/PR guardrail a tool is enabled for).
  toolsRegistry: () => jsonFetch<ToolRegistryEntry[]>("/api/tools/registry"),
  toolAssignments: (workspaceId: number) =>
    jsonFetch<ToolAssignment[]>(`/api/tools/assignments?workspace_id=${workspaceId}`),
  saveToolAssignment: (a: {
    workspace_id: number;
    tool: string;
    on_demand_scan: boolean;
    ci_pipeline: boolean;
    api_scan: boolean;
    pr_guardrail: boolean;
  }) => jsonFetch<ToolAssignment>("/api/tools/assignments", { method: "PUT", body: JSON.stringify(a) }),
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
