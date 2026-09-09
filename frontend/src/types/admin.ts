import type { EnforcementMode } from "./targets";
import type { AiProvider } from "./security";
import type { Nullable } from "@/std-lib";

/**
 * High-level summary of an organization workspace.
 */
export type WorkspaceSummary = {
  id: number;
  name: string;
  organization_id: number;
  enforcement_mode: Nullable<EnforcementMode>;
};

/**
 * Roles assignable to workspace members.
 */
export type WorkspaceRole = "viewer" | "developer" | "security_engineer";

/**
 * Association linking a user to a specific workspace with an assigned role.
 */
export type WorkspaceMembership = {
  id: number;
  user_id: number;
  user_email: string;
  user_name: string;
  workspace_id: number;
  workspace_name: string;
  role: WorkspaceRole;
};

/**
 * Global platform integration and secrets configuration view.
 */
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
  jira_auto_create_severity: Nullable<string>;
  siem_webhook_url_set: boolean;
  siem_export_severity: Nullable<string>;
  encryption_key_healthy: Nullable<boolean>;
};

/**
 * Mutation payload for updating global platform settings and credentials.
 */
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

/**
 * Diagnostic test connection response for third-party integrations (Slack, Jira, SIEM).
 */
export type TestConnectionResult = {
  success: boolean;
  message: string;
};

/**
 * Workspace GitHub PAT status and TTL metadata.
 */
export type GithubTokenView = {
  token_set: boolean;
  created_at: Nullable<string>;
  expires_at: Nullable<string>;
};

/**
 * GitHub organization account installed with a registered GitHub App.
 */
export type GitHubAppInstalledAccount = {
  installation_id: number;
  account_login: string;
  account_type: string;
};

/**
 * GitHub App registration and webhook health metadata.
 */
export type GitHubAppInstallation = {
  id: number;
  app_id: string;
  app_slug: string;
  html_url: string;
  webhook_secret_set: boolean;
  installations: GitHubAppInstalledAccount[];
};
