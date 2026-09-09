import { jsonFetch } from "./client";
import type {
  BuildInfo,
  AuthUser,
  WorkspaceSummary,
  WorkspaceRole,
  WorkspaceMembership,
  ApiToken,
  ApiTokenScope,
  PlatformConfigView,
  UpdateConfigPayload,
  TestConnectionResult,
  GithubTokenView,
  GitHubAppInstallation,
  AuditLogQuery,
  AuditLogResult,
  CommitEvent,
  OrgActivityQuery,
  OrgActivityResult,
  PullRequest,
  SearchResults,
  EnforcementMode,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Returns runtime instance identification and database connection info.
 */
export function buildInfo(): Promise<BuildInfo> {
  return jsonFetch<BuildInfo>("/health");
}

/**
 * Lists all registered users on the platform.
 */
export function users(): Promise<AuthUser[]> {
  return jsonFetch<AuthUser[]>("/api/admin/users");
}

/**
 * Creates a new user account.
 */
export function createUser(u: { email: string; name: string; password: string; role: string }): Promise<AuthUser> {
  return jsonFetch<AuthUser>("/api/admin/users", { method: "POST", body: JSON.stringify(u) });
}

/**
 * Updates a user's global platform role.
 */
export function updateUserRole(id: number, role: string): Promise<AuthUser> {
  return jsonFetch<AuthUser>(`/api/admin/users/${id}/role`, { method: "PATCH", body: JSON.stringify({ role }) });
}

/**
 * Deletes a user account.
 */
export function deleteUser(id: number): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>(`/api/admin/users/${id}`, { method: "DELETE" });
}

/**
 * Lists all workspaces accessible to the organization.
 */
export function workspaces(): Promise<WorkspaceSummary[]> {
  return jsonFetch<WorkspaceSummary[]>("/api/workspaces");
}

/**
 * Updates workspace properties (name or default enforcement mode).
 */
export function updateWorkspace(
  id: number,
  patch: { enforcement_mode?: Nullable<EnforcementMode>; name?: string },
): Promise<WorkspaceSummary> {
  return jsonFetch<WorkspaceSummary>(`/api/workspaces/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
}

/**
 * Retrieves the workspace-wide API ingestion key.
 */
export function workspaceApiKey(
  workspaceId: number,
): Promise<{ workspace_id: number; workspace_name: string; api_key: string }> {
  return jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(
    `/api/workspaces/${workspaceId}/key`,
  );
}

/**
 * Rotates and regenerates the workspace-wide API key.
 */
export function regenerateWorkspaceApiKey(
  workspaceId: number,
): Promise<{ workspace_id: number; workspace_name: string; api_key: string }> {
  return jsonFetch<{ workspace_id: number; workspace_name: string; api_key: string }>(
    `/api/workspaces/${workspaceId}/key/regenerate`,
    { method: "POST" },
  );
}

/**
 * Lists user role memberships for a workspace.
 */
export function workspaceMemberships(workspaceId?: number): Promise<WorkspaceMembership[]> {
  return jsonFetch<WorkspaceMembership[]>(
    `/api/admin/workspace-roles${workspaceId ? `?workspace_id=${workspaceId}` : ""}`,
  );
}

/**
 * Assigns or updates a user's role within a workspace.
 */
export function assignWorkspaceRole(
  userId: number,
  workspaceId: number,
  role: WorkspaceRole,
): Promise<WorkspaceMembership> {
  return jsonFetch<WorkspaceMembership>("/api/admin/workspace-roles", {
    method: "PUT",
    body: JSON.stringify({ user_id: userId, workspace_id: workspaceId, role }),
  });
}

/**
 * Revokes a user's workspace membership.
 */
export function removeWorkspaceMembership(membershipId: number): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>(`/api/admin/workspace-roles/${membershipId}`, { method: "DELETE" });
}

/**
 * Lists all personal access tokens for the authenticated user.
 */
export function apiTokens(): Promise<ApiToken[]> {
  return jsonFetch<ApiToken[]>("/api/api-tokens");
}

/**
 * Generates a new Personal Access Token. Secret token is only returned in this response.
 */
export function createApiToken(name: string, scope: ApiTokenScope): Promise<ApiToken & { token: string }> {
  return jsonFetch<ApiToken & { token: string }>("/api/api-tokens", {
    method: "POST",
    body: JSON.stringify({ name, scope }),
  });
}

/**
 * Revokes a Personal Access Token.
 */
export function revokeApiToken(id: number): Promise<ApiToken> {
  return jsonFetch<ApiToken>(`/api/api-tokens/${id}/revoke`, { method: "POST" });
}

/**
 * Retrieves global platform integrations and credentials configuration.
 */
export function getConfig(): Promise<PlatformConfigView> {
  return jsonFetch<PlatformConfigView>("/api/config");
}

/**
 * Updates global platform configuration settings.
 */
export function updateConfig(payload: UpdateConfigPayload): Promise<PlatformConfigView> {
  return jsonFetch<PlatformConfigView>("/api/config", { method: "POST", body: JSON.stringify(payload) });
}

/**
 * Re-encrypts all stored secrets with the active master encryption key.
 */
export function reseedEncryptionKey(): Promise<{ encryption_key_healthy: boolean }> {
  return jsonFetch<{ encryption_key_healthy: boolean }>("/api/config/encryption-key/reseed", { method: "POST" });
}

/**
 * Tests Slack webhook connectivity.
 */
export function testSlack(webhookUrl?: string): Promise<TestConnectionResult> {
  return jsonFetch<TestConnectionResult>("/api/config/test-slack", {
    method: "POST",
    body: JSON.stringify({ webhook_url: webhookUrl || undefined }),
  });
}

/**
 * Tests Jira API connection credentials.
 */
export function testJira(jiraUrl?: string, apiToken?: string): Promise<TestConnectionResult> {
  return jsonFetch<TestConnectionResult>("/api/config/test-jira", {
    method: "POST",
    body: JSON.stringify({ jira_url: jiraUrl || undefined, jira_api_token: apiToken || undefined }),
  });
}

/**
 * Tests SIEM webhook delivery.
 */
export function testSiem(webhookUrl?: string): Promise<TestConnectionResult> {
  return jsonFetch<TestConnectionResult>("/api/config/test-siem", {
    method: "POST",
    body: JSON.stringify({ webhook_url: webhookUrl || undefined }),
  });
}

/**
 * Fetches workspace GitHub personal access token status.
 */
export function getGithubToken(workspaceId?: number): Promise<GithubTokenView> {
  return jsonFetch<GithubTokenView>(`/api/github-token${workspaceId ? `?workspace_id=${workspaceId}` : ""}`);
}

/**
 * Saves or replaces the GitHub token for a workspace.
 */
export function saveGithubToken(
  token: string,
  expiresInHours: Nullable<number>,
  workspaceId?: number,
): Promise<GithubTokenView> {
  return jsonFetch<GithubTokenView>("/api/github-token", {
    method: "PUT",
    body: JSON.stringify({ token, expires_in_hours: expiresInHours, workspace_id: workspaceId }),
  });
}

/**
 * Deletes the GitHub token for a workspace.
 */
export function deleteGithubToken(workspaceId?: number): Promise<{ token_set: boolean; deleted: boolean }> {
  return jsonFetch<{ token_set: boolean; deleted: boolean }>(
    `/api/github-token${workspaceId ? `?workspace_id=${workspaceId}` : ""}`,
    { method: "DELETE" },
  );
}

/**
 * Validates a GitHub personal access token against the GitHub API.
 */
export function testGithubToken(token?: string, workspaceId?: number): Promise<TestConnectionResult> {
  return jsonFetch<TestConnectionResult>("/api/github-token/test", {
    method: "POST",
    body: JSON.stringify({ token: token || undefined, workspace_id: workspaceId }),
  });
}

/**
 * Retrieves GitHub App configuration and installation health.
 */
export function githubAppStatus(): Promise<{
  apps: GitHubAppInstallation[];
  app_configured: boolean;
  app_slug: Nullable<string>;
  installed: boolean;
  account_login: Nullable<string>;
  webhook_secret_set: boolean;
}> {
  return jsonFetch<{
    apps: GitHubAppInstallation[];
    app_configured: boolean;
    app_slug: Nullable<string>;
    installed: boolean;
    account_login: Nullable<string>;
    webhook_secret_set: boolean;
  }>("/api/github-app/status");
}

/**
 * Generates GitHub App manifest data for one-click setup.
 */
export function githubAppManifestData(
  org?: string,
): Promise<{ manifest: object; post_url: string; webhook_url: string; webhook_reachable: boolean }> {
  return jsonFetch<{ manifest: object; post_url: string; webhook_url: string; webhook_reachable: boolean }>(
    `/api/github-app/manifest-data${org ? `?org=${encodeURIComponent(org)}` : ""}`,
  );
}

/**
 * Synchronizes repositories accessible to the GitHub App.
 */
export function githubAppSync(): Promise<{ created: number }> {
  return jsonFetch<{ created: number }>("/api/github-app/sync", { method: "POST" });
}

/**
 * Updates the webhook secret for GitHub App delivery verification.
 */
export function updateWebhookSecret(
  webhook_secret: string,
  config_id?: number,
): Promise<{ webhook_secret_set: boolean }> {
  return jsonFetch<{ webhook_secret_set: boolean }>("/api/github-app/webhook-secret", {
    method: "PATCH",
    body: JSON.stringify({ webhook_secret, config_id }),
  });
}

/**
 * Retrieves paginated audit log events.
 */
export function auditLog(query: AuditLogQuery = {}): Promise<AuditLogResult> {
  const params = new URLSearchParams();
  if (query.event_type) params.set("event_type", query.event_type);
  if (query.actor) params.set("actor", query.actor);
  if (query.date_from) params.set("date_from", query.date_from);
  if (query.date_to) params.set("date_to", query.date_to);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  return jsonFetch<AuditLogResult>(`/api/audit/log?${params.toString()}`);
}

/**
 * Retrieves the list of distinct actors who have performed audited actions.
 */
export function auditActors(): Promise<string[]> {
  return jsonFetch<string[]>("/api/audit/actors");
}

/**
 * Fetches recent commit activity for a single target repository.
 */
export function activity(targetId: number): Promise<CommitEvent[]> {
  return jsonFetch<CommitEvent[]>(`/api/github/activity/${targetId}`);
}

/**
 * Fetches organization-wide commit activity across all monitored targets.
 */
export function orgActivity(query: OrgActivityQuery = {}): Promise<OrgActivityResult> {
  const params = new URLSearchParams();
  if (query.target_id) params.set("target_id", String(query.target_id));
  if (query.date_from) params.set("date_from", query.date_from);
  if (query.date_to) params.set("date_to", query.date_to);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  return jsonFetch<OrgActivityResult>(`/api/github/org-activity?${params.toString()}`);
}

/**
 * Lists open pull requests for a target repository.
 */
export function prs(targetId: number): Promise<PullRequest[]> {
  return jsonFetch<PullRequest[]>(`/api/github/prs/${targetId}`);
}

/**
 * Performs a global search across findings and target repositories.
 */
export function search(q: string): Promise<SearchResults> {
  return jsonFetch<SearchResults>(`/api/search?q=${encodeURIComponent(q)}`);
}

/**
 * Generates a direct GitHub blob link pointing to a file and optional line number.
 */
export function githubBlobUrl(
  repoUrl: string,
  branch: string,
  filePath: string,
  lineStart?: Nullable<number>,
): string {
  const repoPath = new URL(repoUrl).pathname.replace(/\.git$/, "").replace(/^\//, "");
  const base = `https://github.com/${repoPath}/blob/${branch}/${filePath}`;
  return lineStart ? `${base}#L${lineStart}` : base;
}

/**
 * Formats a workspace display label, disambiguating duplicates with `#id` if names collide.
 */
export function workspaceDisplayName(
  workspace: Pick<WorkspaceSummary, "id" | "name">,
  allWorkspaces: Pick<WorkspaceSummary, "id" | "name">[],
): string {
  const isDuplicate = allWorkspaces.filter((w) => w.name === workspace.name).length > 1;
  return isDuplicate ? `${workspace.name} (#${workspace.id})` : workspace.name;
}
