import { api, type ScanHistoryEntry } from "@/lib/api";
import { settleOrNull } from "@/std-lib";
import { timeAgo } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/status-badge";
import { EmptyState } from "@/components/ui/empty-state";
import { ScanHealthBadge } from "@/components/features/scans";
import { History } from "lucide-react";

function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.slice(0, maxLen) + "…" : str;
}

function duration(entry: ScanHistoryEntry): string {
  if (!entry.completed_at) return "—";
  const ms = new Date(entry.completed_at).getTime() - new Date(entry.started_at).getTime();
  if (ms < 1000) return "<1s";
  const seconds = Math.round(ms / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

// (#276) Per-target scan history, trend over time, rather than the single
// "Last scan" timestamp the overview already shows.
//
// Reads GET /api/scans/history, which is deliberately a separate endpoint
// from /api/scans/summary: that one aggregates to at most one row per
// (target, tool) so list pages never pull a year of history. Here the
// individual rows are the point, so they are returned; scoped to one
// target and paginated, which keeps the property that made the aggregation
// worth doing in the first place.
export async function TargetHistory({ targetId }: { targetId: number }) {
  const history = await settleOrNull(api.scanHistory(targetId));

  if (!history || history.items.length === 0) {
    return (
      <EmptyState
        icon={History}
        title="No scans yet"
        description="Run a scan from this target's header to start building history."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        {history.total} scan{history.total === 1 ? "" : "s"} recorded
        {history.total > history.items.length && <> · showing the {history.items.length} most recent</>}
      </p>

      <Card className="border-border bg-card">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Tool</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                  <th className="px-4 py-2 font-medium">Findings</th>
                  <th className="px-4 py-2 font-medium">Duration</th>
                  <th className="px-4 py-2 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {history.items.map((entry) => (
                  <tr key={entry.scan_id} className="border-b border-border/50 last:border-0">
                    <td className="px-4 py-2.5 text-foreground">{entry.tool}</td>
                    <td className="px-4 py-2.5">
                      <StatusBadge
                        status={entry.status === "completed" ? "completed" : entry.status === "failed" ? "failed" : "running"}
                        size="sm"
                      />
                      {/* Surfaced, not hidden behind a hover: a failed scan
                          whose reason is invisible reads as "nothing
                          happened", which is the shape #253 was about. */}
                      {entry.error && (
                        <span className="ml-2 text-xs text-destructive" title={entry.error}>
                          {truncate(entry.error, 60)}
                        </span>
                      )}
                      {/* (#229) A completed run that was not trusted. The
                          reason sits next to the badge for the same reason
                          the failure reason does above: "not authoritative"
                          alone says something is wrong without saying what
                          to do about it. */}
                      <ScanHealthBadge health={entry.health} className="ml-2 text-[10px]" />
                      {entry.health === "suspect" && entry.health_note && (
                        <p className="mt-1 text-xs text-muted-foreground">{entry.health_note}</p>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">
                      {/* A findings count printed on its own for a run the
                          platform refused to trust is the false all-clear in
                          miniature: "0" reads as clean. It is shown as
                          unknown instead, which is what it is. */}
                      {entry.status !== "completed"
                        ? "—"
                        : entry.health === "suspect"
                          ? `${entry.findings_count} (unverified)`
                          : entry.findings_count}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">{duration(entry)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{timeAgo(entry.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
