import { AlertTriangle, Boxes, GitBranch, ScanLine, ShieldCheck } from "lucide-react";
import { ScanSummaryEntry, Target, TargetSummaryEntry } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { CriticalityChip, GroupBadge } from "@/components/features/targets";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { SeverityChip } from "@/components/ui/severity-chip";
import { PartialFailureBanner } from "@/components/ui/partial-failure-banner";
import { ReloadButton } from "@/components/reload-button";
import { timeAgo } from "@/lib/utils";

// Issue #197: current posture for one target, so a repo owner can answer
// "is my repo OK?" without reading the findings list. Everything here is
// derived from data the page already fetched, no extra round-trips.
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

export function TargetOverview({
  target,
  summaryEntry,
  scanEntry,
  summaryFailed = false,
  scanSummaryFailed = false,
}: {
  target: Target;
  summaryEntry?: TargetSummaryEntry;
  scanEntry?: ScanSummaryEntry;
  /** `/api/targets/summary` did not answer, so `summaryEntry` being absent
   * carries no information about this target. */
  summaryFailed?: boolean;
  /** `/api/scans/summary` did not answer, so `scanEntry` being absent carries
   * no information about whether this target has ever been scanned. */
  scanSummaryFailed?: boolean;
}) {
  /*
   * The counts and the scan history are two independent fetches, and the
   * honesty of this page turns on never letting one stand in for the other.
   *
   * Before this, `unknown` was driven entirely by `lastScan`. So when the scan
   * summary loaded and the target summary did not, the page took the
   * never-scanned escape hatch off the table, read `summaryEntry?.open ?? 0`
   * as a measured zero, and rendered it green, hinted "scanned, nothing open",
   * and captioned "No open findings on the default branch." Four separate
   * assertions of a clean repository, all of them produced by a failed fetch,
   * on the one page a repo owner opens to ask "is my repo OK?".
   *
   * Three states have to stay distinct here (AGENTS.md §1.4, DESIGN_SYSTEM.md
   * §18):
   *   - the fetch failed                       -> unknown
   *   - the map loaded but has no row for this
   *     target, i.e. it was never counted      -> unknown
   *   - the map loaded and says open === 0     -> a real, measured zero
   *
   * The middle case is grouped with unknown deliberately, matching the
   * existing judgement in targets-list.tsx's FindingsColumn: the summary
   * endpoint has no row for a target it has never counted, and "nobody
   * counted" is not "counted zero".
   */
  const countsUnknown = summaryFailed || summaryEntry === undefined;
  const openCount = summaryEntry?.open ?? 0;
  const bySeverity = SEVERITY_ROWS.map((row) => ({
    severity: row.label,
    count: summaryEntry?.[row.key] ?? 0,
  })).filter((s) => s.count > 0);

  const lastScan = scanEntry?.last_scan_at;
  const tools = scanEntry?.tools ?? [];
  // Same distinction on the scan axis: a failed fetch is not evidence of a
  // repository that has never been scanned.
  const scanUnknown = scanSummaryFailed || !lastScan;

  return (
    <div className="flex flex-col gap-6">
      <PartialFailureBanner
        sources={[
          {
            label: "Open-finding counts",
            failed: summaryFailed,
            consequence:
              "This target's posture is shown as unknown rather than clean; it may have open findings that are not counted here.",
          },
          {
            label: "Scan history",
            failed: scanSummaryFailed,
            consequence: "Last-scan time and the tools that ran are not shown.",
          },
        ]}
        action={<ReloadButton />}
      />

      <StatGrid columns={4}>
        <StatCard
          icon={AlertTriangle}
          label="Open findings"
          value={String(openCount)}
          // An unscanned target has zero findings because nobody looked, and a
          // target whose counts failed to load has zero findings because
          // nothing answered. The shared card's `unknown` variant renders an em
          // dash instead of a confident 0, which would read as "clean" (#174).
          unknown={countsUnknown || !lastScan}
          unknownHint={
            summaryFailed
              ? "finding counts unavailable, posture unknown"
              : !lastScan && !scanSummaryFailed
                ? "never scanned, posture unknown"
                : "not counted yet, posture unknown"
          }
          // Green is an assertion. It is only earned by a count that actually
          // came back, against a scan we know happened.
          tone={openCount > 0 ? "attention" : countsUnknown || scanUnknown ? "default" : "positive"}
          hint={openCount === 0 && !countsUnknown && !scanUnknown ? "scanned, nothing open" : undefined}
        />
        <StatCard
          icon={ScanLine}
          label="Last scan"
          value={lastScan ? timeAgo(lastScan) : "Never"}
          unknown={scanUnknown}
          // "no scan history" is a claim about the repository; when the
          // request failed, the only true statement is about the request.
          unknownHint={scanSummaryFailed ? "scan history unavailable" : "no scan history"}
          hint={tools.length > 0 ? tools.join(", ") : undefined}
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
          // Reads as a scan verdict, but it is a routing decision: it
          // decides whether the AI/ML scanners run at all. An external review
          // flagged that the old hint ("no model files or AI dependencies")
          // described the evidence without ever saying what it changes.
          hint={
            target.is_ai_repo_effective
              ? `${target.is_ai_repo_signals || "manually marked"} - AI/ML scanners run on this repo`
              : "no model files or AI dependencies detected - AI/ML scanners are skipped"
          }
        />
      </StatGrid>

      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">Open findings by severity</h2>
        {bySeverity.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {/* Ordered most-uncertain first. The flat "no open findings"
                sentence used to be reachable from a failed fetch, which made
                it the strongest false claim on the page: an empty severity
                list means nothing until you know whether anyone counted. */}
            {countsUnknown
              ? summaryFailed
                ? "Open-finding counts could not be loaded, so this target's posture is unknown rather than clean."
                : "This target has no counted findings yet, so its posture is unknown rather than clean."
              : scanSummaryFailed
                ? "No open findings were counted on the default branch, but scan history is unavailable, so how recently that was measured is unknown."
                : lastScan
                  ? "No open findings on the default branch."
                  : "This target has never been scanned, so its posture is unknown rather than clean."}
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {bySeverity.map(({ severity, count }) => (
              <SeverityChip
                key={severity}
                severity={severity}
                count={count}
                size="sm"
              />
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
