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

export type Target = {
  id: number;
  workspace_id: number;
  name: string;
  repo_url: string;
  default_branch: string;
  label: string;
  criticality_weight: number;
  groups: GroupBadge[];
};

export type Group = {
  id: number;
  workspace_id: number;
  name: string;
  color: string;
  created_at: string;
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
};

export type UpdateConfigPayload = {
  ai_provider?: AiProvider;
  anthropic_api_key?: string;
  openai_compatible_base_url?: string;
  openai_compatible_api_key?: string;
  openai_compatible_model?: string;
};

export function githubBlobUrl(repoUrl: string, branch: string, filePath: string, lineStart?: number | null): string {
  const repoPath = new URL(repoUrl).pathname.replace(/\.git$/, "").replace(/^\//, "");
  const encodedFilePath = filePath.split("/").map(encodeURIComponent).join("/");
  const url = `https://github.com/${repoPath}/blob/${encodeURIComponent(branch)}/${encodedFilePath}`;
  return lineStart ? `${url}#L${lineStart}` : url;
}

export type Summary = { total: number; open: number; mitigated: number };

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

export type WorkspaceSummary = { id: number; name: string; organization_id: number };

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
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    jsonFetch<AuthUser>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => jsonFetch<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  me: () => jsonFetch<AuthUser>("/api/auth/me"),
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
  updateGroup: (id: number, patch: { name?: string; color?: string }) =>
    jsonFetch<Group>(`/api/groups/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteGroup: (id: number) => jsonFetch<{ ok: boolean }>(`/api/groups/${id}`, { method: "DELETE" }),
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
};
