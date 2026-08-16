import { AlertTriangle, Boxes, GitBranch, ScanLine, ShieldCheck } from "lucide-react";
import { ScanSummaryEntry, Target, TargetSummaryEntry } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { CriticalityChip } from "@/components/criticality-chip";
import { GroupBadge } from "@/components/group-badge";
import { SEVERITY_COLOR } from "@/lib/severity";
import { timeAgo } from "@/lib/utils";

// Issue #197: current posture for one target, so a repo owner can answer
// "is my repo OK?" without reading the findings list. Everything here is
// derived from data the page already fetched -- no extra round-trips.
// Counts come from GET /api/targets/summary, never from the findings array
// the page fetched. That array is one *page* of findings, so deriving the
// breakdown from it reported "3 Medium" for a target with 1137 open findings
// the moment this page became properly paginated.
const SEVERITY_ROWS = [
  { label: "Critical", key: "critical" },
  { label: "High", key: "high" },
  { label: "Medium", key: "medium" },
  { label: "Low", key: "low" },
  { label: "Informational", key: "informational" },
] as const;

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <Card className="border-border bg-card py-0">
      <CardContent className="flex items-center gap-3 px-4 py-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-lg font-semibold text-foreground">{value}</div>
          <div className="truncate text-xs text-muted-foreground">{label}</div>
          {hint && <div className="truncate text-[11px] text-muted-foreground/70">{hint}</div>}
        </div>
      </CardContent>
    </Card>
  );
}

export function TargetOverview({
  target,
  summaryEntry,
  scanEntry,
}: {
  target: Target;
  summaryEntry?: TargetSummaryEntry;
  scanEntry?: ScanSummaryEntry;
}) {
  const openCount = summaryEntry?.open ?? 0;
  const bySeverity = SEVERITY_ROWS.map((row) => ({
    severity: row.label,
    count: summaryEntry?.[row.key] ?? 0,
  })).filter((s) => s.count > 0);

  const lastScan = scanEntry?.last_scan_at;
  const tools = scanEntry?.tools ?? [];

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={AlertTriangle}
          label="Open findings"
          value={String(openCount)}
          hint={openCount === 0 && lastScan ? "scanned, nothing open" : undefined}
        />
        <StatCard
          icon={ScanLine}
          label="Last scan"
          // A never-scanned repo says so rather than showing a dash that
          // could read as "nothing found" (#174's principle).
          value={lastScan ? timeAgo(lastScan) : "Never"}
          hint={tools.length > 0 ? tools.join(", ") : "no scan history"}
        />
        <StatCard
          icon={GitBranch}
          label="Default branch"
          value={target.default_branch}
          hint={`risk weight ${target.criticality_weight}/5`}
        />
        <StatCard
          icon={target.is_ai_repo_effective ? Boxes : ShieldCheck}
          label={target.is_ai_repo_effective ? "AI/ML repo" : "Repo type"}
          value={target.is_ai_repo_effective ? "Yes" : "Standard"}
          hint={
            target.is_ai_repo_effective
              ? target.is_ai_repo_signals || "manually marked"
              : "no model files or AI dependencies detected"
          }
        />
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">Open findings by severity</h2>
        {bySeverity.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {lastScan
              ? "No open findings on the default branch."
              : "This target has never been scanned, so its posture is unknown rather than clean."}
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {bySeverity.map(({ severity, count }) => (
              <Badge
                key={severity}
                variant="outline"
                className={`px-2 py-0.5 text-xs font-medium ${SEVERITY_COLOR[severity] ?? ""}`}
              >
                {count} {severity}
              </Badge>
            ))}
          </div>
        )}
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">Classification</h2>
        <div className="flex flex-wrap items-center gap-2">
          <CriticalityChip label={target.label} />
          {target.groups.map((g) => (
            <GroupBadge key={g.id} group={g} />
          ))}
          {target.pipeline_integrated && (
            <Badge variant="outline" className="border-chart-5/40 text-chart-5">
              Pipeline integrated
            </Badge>
          )}
          {target.groups.length === 0 && (
            <span className="text-xs text-muted-foreground">No groups assigned</span>
          )}
        </div>
      </div>
    </div>
  );
}
