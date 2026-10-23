export const SEVERITY_COLOR: Record<string, string> = {
  Critical: "border-destructive/20 bg-destructive/10 text-destructive",
  High: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  Medium: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  Low: "border-border bg-muted text-muted-foreground",
  Informational: "border-border bg-muted text-muted-foreground",
};

// Left-border accent used to give severity a distinct visual anchor on
// finding cards (Snyk/GitHub-style severity-first hierarchy).
export const SEVERITY_BORDER_COLOR: Record<string, string> = {
  Critical: "border-l-destructive",
  High: "border-l-chart-3",
  Medium: "border-l-chart-1",
  Low: "border-l-border",
  Informational: "border-l-border",
};

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

// Shared SeverityChip dot colors; Low and Informational stay neutral.
export const SEVERITY_DOT_COLOR: Record<string, string> = {
  Critical: "bg-destructive",
  High: "bg-chart-3",
  Medium: "bg-chart-1",
  Low: "bg-muted-foreground",
  Informational: "bg-muted-foreground",
};

// Use CSS variables so Recharts colors update when the theme changes.
export const SEVERITY_HEX: Record<string, string> = {
  Critical: "var(--destructive)",
  High: "var(--chart-3)",
  Medium: "var(--chart-1)",
  Low: "var(--muted-foreground)",
  Informational: "var(--muted-foreground)",
};

// KEV (CISA Known Exploited Vulnerabilities) badge, deliberately distinct from the
// severity palette so a KEV-listed finding reads as "confirmed exploited in the wild",
// not just another severity tier.
export const KEV_BADGE_COLOR = "border-destructive/40 bg-destructive/20 text-destructive";

// EPSS (FIRST.org Exploit Prediction Scoring System) badge, shown when the score
// exceeds this threshold. 0.1 == FIRST.org's own "greater than 10% predicted
// probability of exploitation in the next 30 days" notability cutoff.
export const EPSS_NOTABLE_THRESHOLD = 0.1;
export const EPSS_BADGE_COLOR = "border-chart-3/30 bg-chart-3/10 text-chart-3";

// PR Guardrail ignore-request status, separate from finding triage state.
export const IGNORE_STATUS_COLOR: Record<string, string> = {
  none: "border-border bg-muted text-muted-foreground",
  requested: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  approved: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  rejected: "border-destructive/20 bg-destructive/10 text-destructive",
  // Revoked approvals are inactive and use neutral styling.
  revoked: "border-border bg-muted text-muted-foreground",
};

// Keep triage states aligned with the backend OPEN/RESOLVED_FINDING_STATES.
export const OPEN_FINDING_STATES = ["Open", "Reopened"];
export const RESOLVED_FINDING_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Mitigated"];
export const FINDING_STATE_ORDER = [...OPEN_FINDING_STATES, ...RESOLVED_FINDING_STATES];

export const STATE_COLOR: Record<string, string> = {
  Open: "text-destructive",
  "Accepted Risk": "text-chart-3",
  "False Positive": "text-muted-foreground",
  "Won't Fix": "text-muted-foreground",
  Mitigated: "text-chart-5",
  Reopened: "text-chart-3",
};

// Labels and colors for the admin security audit log.
export const AUTH_EVENT_LABEL: Record<string, string> = {
  login_success: "Login",
  login_failed: "Failed login",
  logout: "Logout",
  password_changed: "Password changed",
  role_changed: "Role changed",
  workspace_role_changed: "Workspace role changed",
  workspace_role_removed: "Workspace role removed",
  target_deactivated: "Target deactivated",
  target_reactivated: "Target reactivated",
  target_deleted: "Target deleted",
};

export const AUTH_EVENT_COLOR: Record<string, string> = {
  login_success: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  login_failed: "border-destructive/20 bg-destructive/10 text-destructive",
  logout: "border-border bg-muted text-muted-foreground",
  password_changed: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  role_changed: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  workspace_role_changed: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  workspace_role_removed: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  // Deactivation is consequential; deletion removes the repository from posture views.
  target_deactivated: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  target_reactivated: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  target_deleted: "border-destructive/20 bg-destructive/10 text-destructive",
};
