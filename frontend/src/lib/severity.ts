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

export const STATE_COLOR: Record<string, string> = {
  Open: "text-destructive",
  "Accepted Risk": "text-chart-3",
  "False Positive": "text-muted-foreground",
  "Won't Fix": "text-muted-foreground",
  Mitigated: "text-chart-5",
  Reopened: "text-chart-3",
};
