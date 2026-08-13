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

export const SEVERITY_HEX: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f59e0b",
  Medium: "#3b82f6",
  Low: "#6b7280",
  Informational: "#6b7280",
};

// KEV (CISA Known Exploited Vulnerabilities) badge — deliberately distinct from the
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
};

export const STATE_COLOR: Record<string, string> = {
  Open: "text-destructive",
  "Accepted Risk": "text-chart-3",
  "False Positive": "text-muted-foreground",
  "Won't Fix": "text-muted-foreground",
  Mitigated: "text-chart-5",
  Reopened: "text-chart-3",
};
