"use client";

import { useEffect, useState, useCallback } from "react";
import { api, PrGuardrailFinding, PrGuardrailLogEntry } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { IGNORE_STATUS_COLOR, SEVERITY_COLOR } from "@/lib/severity";

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

function RequestIgnoreAction({ finding, onRequested }: { finding: PrGuardrailFinding; onRequested: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      await api.requestIgnoreFinding(finding.id, reason);
      setOpen(false);
      setReason("");
      onRequested();
    } finally {
      setSubmitting(false);
    }
  }

  if (finding.ignore_status !== "none") return null;

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
        Request Ignore
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

function PrGuardrailFindingRow({ finding, onChanged }: { finding: PrGuardrailFinding; onChanged: () => void }) {
  return (
    <div className="rounded-md border border-border bg-secondary/40 px-3 py-2">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className={`shrink-0 px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity] || "text-muted-foreground"}`}
            >
              {finding.severity}
            </Badge>
            <span className="truncate text-xs font-medium text-foreground">{finding.title}</span>
          </div>
          <div className="mt-1 truncate text-xs text-muted-foreground">
            {finding.tool} · {finding.file_path}
            {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
          </div>
          {finding.ignore_status === "requested" && (
            <div className="mt-1 text-xs text-muted-foreground">
              Ignore requested by {finding.ignore_requested_by}: {finding.ignore_requested_reason}
            </div>
          )}
          {(finding.ignore_status === "approved" || finding.ignore_status === "rejected") && (
            <div className="mt-1 text-xs text-muted-foreground">
              Ignore {finding.ignore_status} by {finding.ignore_reviewed_by}
              {finding.ignore_reviewed_at ? ` · ${new Date(finding.ignore_reviewed_at).toLocaleString()}` : ""}
            </div>
          )}
        </div>
        <Badge variant="outline" className={`shrink-0 ${IGNORE_STATUS_COLOR[finding.ignore_status] || "text-muted-foreground"}`}>
          {finding.ignore_status}
        </Badge>
      </div>
      <div className="mt-2">
        <RequestIgnoreAction finding={finding} onRequested={onChanged} />
      </div>
    </div>
  );
}

function ScanFindings({ scanId }: { scanId: number }) {
  const [findings, setFindings] = useState<PrGuardrailFinding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .getPrGuardrailFindings(scanId)
      .then(setFindings)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load findings"));
  }, [scanId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (error) return <p className="text-xs text-destructive">{error}</p>;
  if (findings === null) return <p className="text-xs text-muted-foreground">Loading findings...</p>;
  if (findings.length === 0) return <p className="text-xs text-muted-foreground">No persisted findings for this scan.</p>;

  return (
    <div className="flex flex-col gap-2">
      {findings.map((f) => (
        <PrGuardrailFindingRow key={f.id} finding={f} onChanged={refresh} />
      ))}
    </div>
  );
}

export function PrGuardrailLog({ targetId }: { targetId: number | null }) {
  const [log, setLog] = useState<PrGuardrailLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

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
        {log.map((entry) => {
          const isExpanded = expanded === entry.id;
          return (
            <Card key={entry.id} className="border-border bg-card">
              <CardContent className="px-4 py-3">
                <button
                  className="flex w-full items-center justify-between gap-3 text-left"
                  onClick={() => setExpanded(isExpanded ? null : entry.id)}
                >
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
                    <span className="text-xs text-muted-foreground">
                      {entry.new_endpoints_count} new endpoint{entry.new_endpoints_count === 1 ? "" : "s"}
                    </span>
                  </div>
                </button>

                {entry.status === "blocked" && (
                  <div className="mt-2">
                    <OverrideAction entry={entry} onOverridden={refresh} />
                  </div>
                )}

                {isExpanded && (
                  <div className="mt-3 border-t border-border pt-3">
                    <ScanFindings scanId={entry.id} />
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
        {!loading && log.length === 0 && (
          <p className="text-sm text-muted-foreground">No PR Guardrail scans yet for this target.</p>
        )}
      </div>
    </div>
  );
}
