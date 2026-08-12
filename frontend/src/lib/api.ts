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
  first_seen: string;
  last_seen: string;
};

export type Summary = { total: number; open: number; mitigated: number };

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
export type Endpoint = { framework: string; method: string; route: string; file: string; line: number };
export type AuditEvent = { type: string; timestamp: string; actor: string; summary: string; reason: string };

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
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
  findings: (targetId?: number, state?: string) => {
    const params = new URLSearchParams();
    if (targetId) params.set("target_id", String(targetId));
    if (state) params.set("state", state);
    return jsonFetch<Finding[]>(`/api/findings?${params.toString()}`);
  },
  triage: (findingId: number, toState: string, reason: string) =>
    jsonFetch<Finding>(
      `/api/findings/${findingId}/triage?to_state=${encodeURIComponent(toState)}&reason=${encodeURIComponent(reason)}`,
      { method: "POST" }
    ),
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
  runDiscovery: (targetId: number) =>
    jsonFetch<{ target_id: number; count: number; endpoints: Endpoint[] }>(`/api/discovery/${targetId}`, { method: "POST" }),
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
    jsonFetch<{ app_configured: boolean; app_slug: string | null; installed: boolean; account_login: string | null }>(
      "/api/github-app/status"
    ),
  githubAppManifestData: (org?: string) =>
    jsonFetch<{ manifest: object; post_url: string }>(`/api/github-app/manifest-data${org ? `?org=${encodeURIComponent(org)}` : ""}`),
  githubAppSync: () => jsonFetch<{ created: number }>("/api/github-app/sync", { method: "POST" }),
  getConfig: () => jsonFetch<{ anthropic_api_key_set: boolean }>("/api/config"),
  updateConfig: (anthropic_api_key: string) =>
    jsonFetch<{ anthropic_api_key_set: boolean }>("/api/config", { method: "POST", body: JSON.stringify({ anthropic_api_key }) }),
  toolsHealth: () =>
    jsonFetch<{ tool: string; installed: boolean; version: string | null; response_ms: number | null }[]>(
      "/api/tools/health"
    ),
};
