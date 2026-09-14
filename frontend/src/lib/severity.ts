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

// CSS custom-property references, not literal hex; these feed recharts
// `fill`/Cell colors (see components/charts/severity-pie.tsx), which accept
// `var(--x)` in both the fill attribute and inline style, and modern
// browsers resolve them live against the current `:root`/`:root[data-theme]`
// cascade. Kept as *tokens*, not hex, so the severity pie chart actually
// re-colors on theme toggle instead of freezing at whatever it rendered
// first; the same partial-theming failure mode called out in #115's
// acceptance criteria, just in chart form instead of CSS form.
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

// PR Guardrail finding ignore-request lifecycle (developer requests ->
// security engineer/admin approves or rejects). Deliberately distinct from
// SEVERITY_COLOR/STATE_COLOR since it tracks the ignore workflow, not the
// finding's own severity/triage state.
export const IGNORE_STATUS_COLOR: Record<string, string> = {
  none: "border-border bg-muted text-muted-foreground",
  requested: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  approved: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  rejected: "border-destructive/20 bg-destructive/10 text-destructive",
  // An approval later undone (app/api/pr_guardrail.py's revoke_ignore) --
  // neutral, same treatment as "none", since it's an inactive/settled state
  // like rejected, not something currently blocking anyone's attention.
  revoked: "border-border bg-muted text-muted-foreground",
};

// Triage states, split the way the backend splits them
// (app/models/models.py's OPEN_FINDING_STATES / RESOLVED_FINDING_STATES):
// "still needs attention" vs "already triaged". Kept here, next to
// STATE_COLOR, as the one frontend definition every state picker imports --
// the Findings page's filter bar narrows to one half depending on which tab
// is active, the Reports page's report builder (#302) offers all of them,
// and a third hand-written copy is how those two come to disagree about
// whether "Reopened" is open.
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

// Security audit log (admin-only, login/logout/permission-change activity;
// see app/(dashboard)/admin/security-log.tsx). A failed login is the one
// event here that's an active signal to look at, hence the destructive
// treatment shared with a finding's Open state; permission changes get the
// same amber as Accepted Risk/Reopened (a decision worth noticing, not
// necessarily a bad one) rather than a color of their own.
export const AUTH_EVENT_LABEL: Record<string, string> = {
  login_success: "Login",
  login_failed: "Failed login",
  logout: "Logout",
  password_changed: "Password changed",
  role_changed: "Role changed",
  workspace_role_changed: "Workspace role changed",
  workspace_role_removed: "Workspace role removed",
  // (#273) Target lifecycle. Deliberately worded as what happened to the
  // repository rather than as a generic "target updated": these rows are
  // read to answer "why did this repo stop being scanned" and "who removed
  // the record of these findings", and the label is the first thing that
  // has to answer it.
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
  // Deactivation is amber like a permission change: consequential, not
  // necessarily bad. Deletion gets the destructive treatment shared with a
  // failed login -- it is the one event here that removes a repository from
  // every posture surface at once, and it should be the row an admin's eye
  // lands on when scanning this log.
  target_deactivated: "border-chart-3/20 bg-chart-3/10 text-chart-3",
  target_reactivated: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  target_deleted: "border-destructive/20 bg-destructive/10 text-destructive",
};
