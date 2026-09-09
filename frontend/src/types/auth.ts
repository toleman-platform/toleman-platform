/**
 * Authentication, User Management, API Tokens, and Audit Logging types.
 */

import type { Nullable } from "@/std-lib";

/**
 * Authenticated user profile returned by /api/auth/me and user admin APIs.
 */
export type AuthUser = {
  /** Database ID of the user */
  id: number;
  /** Primary login email */
  email: string;
  /** Full human name or display moniker */
  name: string;
  /** Global platform role (e.g. "admin", "viewer", "developer", "security_engineer") */
  role: string;
};

/**
 * Delivery channels supported by the platform notification subsystem.
 */
export type NotificationChannel = "email" | "slack";

/**
 * Security event types that can trigger automated user notifications.
 */
export type NotificationEventType =
  | "critical_finding"
  | "kev_cve"
  | "sla_breach"
  | "scan_failure"
  | "malicious_package";

/**
 * User subscription preference for an event type across a delivery channel.
 */
export type NotificationPreference = {
  channel: NotificationChannel;
  event_type: NotificationEventType;
  enabled: boolean;
};

/**
 * Permission scope for Personal Access Tokens (PATs) used with /api/public/v1/*.
 */
export type ApiTokenScope = "read" | "read_write";

/**
 * Personal Access Token metadata (token secret is omitted after creation).
 */
export type ApiToken = {
  id: number;
  name: string;
  token_prefix: string;
  scope: ApiTokenScope;
  created_at: string;
  last_used_at: Nullable<string>;
  revoked_at: Nullable<string>;
};

/**
 * Finding state change details nested inside an AuditEvent.
 */
export type AuditEventExpandItem = {
  finding_id: number;
  title: Nullable<string>;
  from_state: string;
  to_state: string;
  timestamp: string;
};

/**
 * Immutable audit log record capturing security actions and administrative changes.
 */
export type AuditEvent = {
  type: string;
  timestamp: string;
  actor: string;
  summary: string;
  reason: string;
  grouped_count: number;
  expand: Nullable<AuditEventExpandItem[]>;
};

/**
 * Query filter parameters for retrieving paginated audit log entries.
 */
export type AuditLogQuery = {
  event_type?: string;
  actor?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  page_size?: number;
};

/**
 * Paginated envelope for audit log entries.
 */
export type AuditLogResult = {
  items: AuditEvent[];
  total: number;
};
