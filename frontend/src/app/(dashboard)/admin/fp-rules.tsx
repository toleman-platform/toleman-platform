"use client";

import { useState } from "react";
import { api, FalsePositiveRule, FpRuleStats, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { Ban, Building2, RotateCcw, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";

// Issue #76: false-positive learning engine -- rules here are learned
// automatically the moment a finding is triaged "False Positive" (see
// app.core.fp_learning), not created from this page. This is the "an
// auto-suppress engine a user can't inspect or undo is a real product bug"
// surface: view what's being auto-suppressed, expire (soft-disable) or
// permanently revoke a rule, or widen a narrowly-scoped one to "any file"
// for that rule_id/tool.
export function FpRules() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data,
    error: loadError,
    isInitialLoading: loading,
    refetch,
  } = useAsyncData<[FalsePositiveRule[], FpRuleStats]>(
    () => Promise.all([api.fpRules(workspaceId!), api.fpRuleStats(workspaceId!)]),
    { enabled: workspaceId != null, deps: [workspaceId] },
  );
  const [rules, stats] = data ?? [null, null];

  // The workspace list failing is worth surfacing on its own: without it an
  // empty picker reads as "this deployment has no workspaces".
  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  async function mutate(action: () => Promise<unknown>, failureMessage: string) {
    if (!workspaceId) return;
    setMutationError(null);
    try {
      await action();
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : failureMessage);
    }
  }

  const toggleActive = (rule: FalsePositiveRule) =>
    mutate(() => api.setFpRuleActive(rule.id, !rule.active), "failed to update rule");
  const widen = (rule: FalsePositiveRule) => mutate(() => api.widenFpRule(rule.id), "failed to widen rule");
  const remove = (rule: FalsePositiveRule) => mutate(() => api.deleteFpRule(rule.id), "failed to delete rule");

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <div className="font-medium text-foreground">False Positive Rules</div>
              <div className="text-xs text-muted-foreground">
                Learned automatically when a finding is marked &quot;False Positive&quot; -- matches (same rule +
                tool, same filename) are auto-suppressed on future scans anywhere in this workspace, including a
                different repo. Expire a rule to stop it firing, widen it to match any file, or delete it entirely.
              </div>
            </div>
          </div>

          {workspaces === null ? (
            <SkeletonList count={1} />
          ) : workspaces.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="No workspaces yet"
              description="Connect a target first to create a workspace."
              bare
            />
          ) : (
            <select
              aria-label="Workspace"
              className="w-fit rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={workspaceId ?? ""}
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {workspaceDisplayName(w, workspaces)}
                </option>
              ))}
            </select>
          )}

          {workspaceId != null && stats && (
            <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
              <span>
                <span className="font-medium text-foreground">{stats.active_rules}</span> active rule
                {stats.active_rules === 1 ? "" : "s"}
              </span>
              <span>
                <span className="font-medium text-foreground">{stats.total_matches}</span> findings auto-suppressed
                (lifetime)
              </span>
            </div>
          )}

          {error && <p className="text-xs text-destructive">{error}</p>}

          {workspaceId != null && (
            <div className="flex flex-col divide-y divide-border rounded-md border border-border">
              {loading ? (
                <div className="px-3 py-2">
                  <SkeletonList count={2} />
                </div>
              ) : !rules || rules.length === 0 ? (
                <EmptyState
                  icon={ShieldOff}
                  title="No false-positive rules learned yet"
                  description={'For this workspace -- triage a finding as "False Positive" to teach one.'}
                  bare
                />
              ) : (
                rules.map((r) => (
                  <div key={r.id} className="flex items-center justify-between gap-3 px-3 py-2">
                    <div className="flex flex-col gap-0.5">
                      <div className="flex items-center gap-2 text-sm text-foreground">
                        <span className="font-medium">{r.rule_id}</span>
                        <span className="text-xs text-muted-foreground">({r.tool})</span>
                        {!r.active && (
                          <span className="inline-flex items-center rounded-full border border-border px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                            expired
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {r.file_path_pattern ? (
                          <>files named <span className="font-mono">{r.file_path_pattern}</span></>
                        ) : (
                          "any file"
                        )}
                        {" · "}
                        matched {r.match_count} time{r.match_count === 1 ? "" : "s"}
                        {r.last_matched_at ? ` · last ${r.last_matched_at.slice(0, 10)}` : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {r.file_path_pattern && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="shrink-0 text-xs text-muted-foreground hover:text-foreground"
                          onClick={() => widen(r)}
                          aria-label={`Widen rule ${r.rule_id} to match any file`}
                        >
                          Widen to any file
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0 text-muted-foreground hover:text-foreground"
                        onClick={() => toggleActive(r)}
                        aria-label={r.active ? `Expire rule ${r.rule_id}` : `Reactivate rule ${r.rule_id}`}
                        title={r.active ? "Expire (stop auto-suppressing)" : "Reactivate"}
                      >
                        {r.active ? <Ban className="h-4 w-4" /> : <RotateCcw className="h-4 w-4" />}
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0 text-muted-foreground hover:text-destructive"
                        onClick={() => remove(r)}
                        aria-label={`Delete rule ${r.rule_id}`}
                        title="Delete permanently"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
