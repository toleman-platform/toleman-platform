import { api, ScanHistoryEntry } from "@/lib/api";
import { settleOrNull } from "@/lib/settle";
import { timeAgo } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { History } from "lucide-react";

const STATUS_CLASS: Record<string, string> = {
  completed: "border-emerald-600/30 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  failed: "border-destructive/30 bg-destructive/10 text-destructive",
  running: "border-border bg-muted text-muted-foreground",
};

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
                    <td className="px-4 py-2 text-foreground">{entry.tool}</td>
                    <td className="px-4 py-2">
                      <Badge
                        variant="outline"
                        className={`text-[10px] ${STATUS_CLASS[entry.status] ?? "text-muted-foreground"}`}
                      >
                        {entry.status}
                      </Badge>
                      {/* Surfaced, not hidden behind a hover: a failed scan
                          whose reason is invisible reads as "nothing
                          happened", which is the shape #253 was about. */}
                      {entry.error && (
                        <span className="ml-2 text-xs text-destructive" title={entry.error}>
                          {entry.error.length > 60 ? `${entry.error.slice(0, 60)}…` : entry.error}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground">
                      {entry.status === "completed" ? entry.findings_count : "—"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{duration(entry)}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{timeAgo(entry.started_at)}</td>
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
