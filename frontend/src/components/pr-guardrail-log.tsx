"use client";

import { useEffect, useState, useCallback } from "react";
import { api, PrGuardrailLogEntry } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const LOG_STATUS_COLOR: Record<string, string> = {
  running: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  passed: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  blocked: "border-destructive/20 bg-destructive/10 text-destructive",
  error: "border-border bg-muted text-muted-foreground",
  overridden: "border-chart-3/20 bg-chart-3/10 text-chart-3",
};

function OverrideAction({ entry, onOverridden }: { entry: PrGuardrailLogEntry; onOverridden: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      await api.overridePrGuardrail(entry.id, reason);
      setOpen(false);
      setReason("");
      onOverridden();
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
        Override (Accept Risk)
      </button>
    );
  }

  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <Input
        className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
        placeholder="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      <Button size="sm" variant="outline" disabled={submitting || !reason} onClick={submit} className="h-7 text-xs">
        Confirm
      </Button>
      <button onClick={() => setOpen(false)} className="text-xs text-muted-foreground">
        cancel
      </button>
    </div>
  );
}

export function PrGuardrailLog({ targetId }: { targetId: number | null }) {
  const [log, setLog] = useState<PrGuardrailLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    if (targetId === null) return;
    setLoading(true);
    setError(null);
    api
      .getPrGuardrailLog(targetId)
      .then(setLog)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load PR guardrail log"))
      .finally(() => setLoading(false));
  }, [targetId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (targetId === null) return null;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="text-lg font-semibold text-foreground">PR Audit &amp; Discovery Log</h2>
        <p className="text-sm text-muted-foreground">History of PR Guardrail scans for this target.</p>
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading...</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="flex flex-col gap-2">
        {log.map((entry) => (
          <Card key={entry.id} className="border-border bg-card">
            <CardContent className="px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-foreground">
                    #{entry.pr_number} {entry.pr_title}
                  </div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">
                    {entry.branch} · created {new Date(entry.created_at).toLocaleString()}
                    {entry.completed_at ? ` · completed ${new Date(entry.completed_at).toLocaleString()}` : ""}
                  </div>
                  {entry.status === "overridden" && entry.override_reason && (
                    <div className="mt-1 text-xs text-muted-foreground">Override reason: {entry.override_reason}</div>
                  )}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <Badge variant="outline" className={LOG_STATUS_COLOR[entry.status] || "text-muted-foreground"}>
                    {entry.status}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {entry.new_findings_count} new finding{entry.new_findings_count === 1 ? "" : "s"}
                    {entry.highest_new_severity ? ` · highest: ${entry.highest_new_severity}` : ""}
                  </span>
                </div>
              </div>

              {entry.status === "blocked" && (
                <div className="mt-2">
                  <OverrideAction entry={entry} onOverridden={refresh} />
                </div>
              )}
            </CardContent>
          </Card>
        ))}
        {!loading && log.length === 0 && (
          <p className="text-sm text-muted-foreground">No PR Guardrail scans yet for this target.</p>
        )}
      </div>
    </div>
  );
}
