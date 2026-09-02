"use client";

import { useState } from "react";
import { api, PrGuardrailFinding } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { SeverityChip } from "@/components/ui/severity-chip";
import { AlertBanner } from "@/components/ui/alert-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { CheckCircle2 } from "lucide-react";

export function ApprovalQueue() {
  const [busyId, setBusyId] = useState<number | null>(null);

  const {
    data: findings,
    error: loadError,
    refetch: refresh,
  } = useAsyncData<PrGuardrailFinding[]>(() => api.getPendingIgnoreRequests());
  const error = loadError?.message ?? null;

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
      {error && <AlertBanner tone="critical">{error}</AlertBanner>}
      {findings === null && !error && <SkeletonList count={3} />}

      {findings !== null && (
        <div className="flex flex-col gap-2">
          {findings.map((f) => (
            <Card key={f.id} className="border-border bg-card">
              <CardContent className="px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <SeverityChip severity={f.severity} size="sm" />
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
            <EmptyState
              icon={CheckCircle2}
              title="No pending ignore requests"
              description="PR Guardrail findings a developer has requested be ignored will appear here."
            />
          )}
        </div>
      )}
    </div>
  );
}
