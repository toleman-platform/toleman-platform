const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Target = {
  id: number;
  workspace_id: number;
  name: string;
  repo_url: string;
  default_branch: string;
  label: string;
  criticality_weight: number;
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
  state?: string;
  severity?: string;
  tool?: string;
  search?: string;
  page?: number;
  page_size?: number;
};

export type AuthUser = { id: number; email: string; name: string; role: string };

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
export type AuditEvent = { type: string; timestamp: string; actor: string; summary: string; reason: string };

export type SearchResults = { findings: Finding[]; targets: Target[] };

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
  targets: () => jsonFetch<Target[]>("/api/targets"),
  target: (id: number) => jsonFetch<Target>(`/api/targets/${id}`),
  createTarget: (t: Partial<Target>) =>
    jsonFetch<Target>("/api/targets", { method: "POST", body: JSON.stringify(t) }),
  findings: (query: FindingsQuery = {}) => {
    const params = new URLSearchParams();
    if (query.target_id) params.set("target_id", String(query.target_id));
    if (query.state) params.set("state", query.state);
    if (query.severity) params.set("severity", query.severity);
    if (query.tool) params.set("tool", query.tool);
    if (query.search) params.set("search", query.search);
    if (query.page) params.set("page", String(query.page));
    if (query.page_size) params.set("page_size", String(query.page_size));
    return jsonFetch<FindingListResult>(`/api/findings?${params.toString()}`);
  },
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
  runScan: (targetId: number, tool: string) =>
    jsonFetch<{ scan_id: number; ingested: number } | { error: string }>(
      `/api/scans/run?target_id=${targetId}&tool=${tool}`,
      { method: "POST" }
    ),
  updateTarget: (id: number, patch: Partial<Target>) =>
    jsonFetch<Target>(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  workspaceKey: (targetId: number) =>
    jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(`/api/targets/${targetId}/workspace-key`),
  activity: (targetId: number) => jsonFetch<CommitEvent[]>(`/api/github/activity/${targetId}`),
  orgActivity: () => jsonFetch<(CommitEvent & { target: string })[]>("/api/github/org-activity"),
  prs: (targetId: number) => jsonFetch<PullRequest[]>(`/api/github/prs/${targetId}`),
  getDiscoveredEndpoints: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; endpoints: Endpoint[] }>(`/api/discovery/${targetId}`),
  runDiscovery: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; new_count: number; endpoints: Endpoint[] }>(
      `/api/discovery/${targetId}`,
      { method: "POST" }
    ),
  getSbom: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; components: SbomComponent[] }>(`/api/sbom/${targetId}`),
  generateSbom: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; new_count: number; components: SbomComponent[] }>(
      `/api/sbom/${targetId}`,
      { method: "POST" }
    ),
  aiStatus: () => jsonFetch<{ configured: boolean }>("/api/ai/status"),
  analyzeFinding: (findingId: number) =>
    jsonFetch<{ finding_id: number; analysis: string }>(`/api/ai/analyze/${findingId}`, { method: "POST" }),
  auditLog: () => jsonFetch<AuditEvent[]>("/api/audit/log"),
  users: () => jsonFetch<AuthUser[]>("/api/admin/users"),
  createUser: (u: { email: string; name: string; password: string; role: string }) =>
    jsonFetch<AuthUser>("/api/admin/users", { method: "POST", body: JSON.stringify(u) }),
  updateUserRole: (id: number, role: string) =>
    jsonFetch<AuthUser>(`/api/admin/users/${id}/role`, { method: "PATCH", body: JSON.stringify({ role }) }),
  deleteUser: (id: number) => jsonFetch<{ ok: boolean }>(`/api/admin/users/${id}`, { method: "DELETE" }),
  githubAppStatus: () =>
    jsonFetch<{
      app_configured: boolean;
      app_slug: string | null;
      installed: boolean;
      account_login: string | null;
      webhook_secret_set: boolean;
    }>("/api/github-app/status"),
  githubAppManifestData: (org?: string) =>
    jsonFetch<{ manifest: object; post_url: string }>(`/api/github-app/manifest-data${org ? `?org=${encodeURIComponent(org)}` : ""}`),
  githubAppSync: () => jsonFetch<{ created: number }>("/api/github-app/sync", { method: "POST" }),
  updateWebhookSecret: (webhook_secret: string) =>
    jsonFetch<{ webhook_secret_set: boolean }>("/api/github-app/webhook-secret", {
      method: "PATCH",
      body: JSON.stringify({ webhook_secret }),
    }),
  getConfig: () => jsonFetch<{ anthropic_api_key_set: boolean }>("/api/config"),
  updateConfig: (anthropic_api_key: string) =>
    jsonFetch<{ anthropic_api_key_set: boolean }>("/api/config", { method: "POST", body: JSON.stringify({ anthropic_api_key }) }),
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
