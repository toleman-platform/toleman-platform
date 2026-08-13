"use client";

import { useCallback, useEffect, useState } from "react";
import { api, PrGuardrailFinding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { SEVERITY_COLOR } from "@/lib/severity";

export function ApprovalQueue() {
  const [findings, setFindings] = useState<PrGuardrailFinding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const refresh = useCallback(() => {
    setError(null);
    api
      .getPendingIgnoreRequests()
      .then(setFindings)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load pending ignore requests"));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function approve(id: number) {
    setBusyId(id);
    try {
      await api.approveIgnore(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function reject(id: number) {
    setBusyId(id);
    try {
      await api.rejectIgnore(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-lg font-semibold text-foreground">Approval Queue</h2>
        <p className="text-sm text-muted-foreground">
          PR Guardrail findings a developer has requested be ignored, pending security review.
        </p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {findings === null && !error && <SkeletonList count={3} />}

      {findings !== null && (
        <div className="flex flex-col gap-2">
          {findings.map((f) => (
            <Card key={f.id} className="border-border bg-card">
              <CardContent className="px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge
                        variant="outline"
                        className={`shrink-0 px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEVERITY_COLOR[f.severity] || "text-muted-foreground"}`}
                      >
                        {f.severity}
                      </Badge>
                      <span className="truncate text-sm font-medium text-foreground">{f.title}</span>
                    </div>
                    <div className="mt-1 truncate text-xs text-muted-foreground">
                      {f.tool} · {f.file_path}
                      {f.line_start ? `:${f.line_start}` : ""} · {f.rule_id}
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      Requested by {f.ignore_requested_by}: {f.ignore_requested_reason}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busyId === f.id}
                      onClick={() => approve(f.id)}
                      className="h-7 text-xs"
                    >
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busyId === f.id}
                      onClick={() => reject(f.id)}
                      className="h-7 text-xs text-destructive"
                    >
                      Reject
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {findings.length === 0 && (
            <p className="text-sm text-muted-foreground">No pending ignore requests.</p>
          )}
        </div>
      )}
    </div>
  );
}
