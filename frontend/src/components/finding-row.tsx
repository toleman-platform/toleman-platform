"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Finding, api } from "@/lib/api";
import { SEVERITY_BORDER_COLOR, SEVERITY_COLOR, STATE_COLOR } from "@/lib/severity";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

export function FindingRow({
  finding,
  selectable = false,
  selected = false,
  onSelectChange,
}: {
  finding: Finding;
  selectable?: boolean;
  selected?: boolean;
  onSelectChange?: (checked: boolean) => void;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function triage(toState: string) {
    setSubmitting(true);
    try {
      await api.triage(finding.id, toState, reason);
      setOpen(false);
      setReason("");
      router.refresh();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className={`border-border bg-card border-l-4 ${SEVERITY_BORDER_COLOR[finding.severity]}`}>
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-start gap-3">
            {selectable && (
              <input
                type="checkbox"
                aria-label={`Select finding ${finding.title}`}
                className="mt-1 h-4 w-4 shrink-0 accent-primary"
                checked={selected}
                onChange={(e) => onSelectChange?.(e.target.checked)}
              />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Badge
                  variant="outline"
                  className={`shrink-0 px-2 py-0.5 text-sm font-bold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity]}`}
                >
                  {finding.severity}
                </Badge>
                <span className="truncate text-sm font-medium text-foreground">{finding.title}</span>
              </div>
              <div className="mt-1 truncate text-xs text-muted-foreground">
                {finding.tool} · {finding.file_path}
                {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
              </div>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="font-mono text-sm text-foreground">{finding.priority_score}</div>
            <div className={`text-xs ${STATE_COLOR[finding.state] || "text-muted-foreground"}`}>{finding.state}</div>
          </div>
        </div>

        <div className="mt-2">
          {!open ? (
            <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
              Triage
            </button>
          ) : (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Input
                className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
                placeholder="Reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
              {TRIAGE_STATES.map((s) => (
                <Button key={s} size="sm" variant="outline" disabled={submitting} onClick={() => triage(s)} className="h-7 text-xs">
                  {s}
                </Button>
              ))}
              <button onClick={() => setOpen(false)} className="text-xs text-muted-foreground">
                cancel
              </button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
