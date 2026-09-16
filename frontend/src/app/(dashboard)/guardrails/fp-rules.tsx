"use client";

import { useState } from "react";
import { api, FalsePositiveRule, FpRuleStats } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Ban, Building2, RotateCcw, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";

// Issue #76: false-positive learning engine; rules here are learned
// automatically the moment a finding is triaged "False Positive" (see
// app.core.fp_learning), not created from this page. This is the "an
// auto-suppress engine a user can't inspect or undo is a real product bug"
// surface: view what's being auto-suppressed, expire (soft-disable) or
// permanently revoke a rule, or widen a narrowly-scoped one to "any file"
// for that rule_id/tool.
export function FpRules() {
  // (#506) Follows the global workspace switcher instead of owning its own
  // picker; this surface has no "all workspaces" view (auto-suppression is
  // inherently per-workspace), so a null activeWorkspaceId ("All
  // workspaces") renders a prompt below rather than fetching anything.
  const { activeWorkspaceId: workspaceId, error: workspacesError } = useWorkspaceContext();
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data,
    status,
    isRefreshing,
    error: loadError,
    refetch,
  } = useAsyncData<[FalsePositiveRule[], FpRuleStats]>(
    () => Promise.all([api.fpRules(workspaceId!), api.fpRuleStats(workspaceId!)]),
    { enabled: workspaceId != null, deps: [workspaceId] },
  );
  // useAsyncData keeps the previous workspace's rules on screen while the
  // new workspace's request is in flight; without this, a widen/delete click
  // during that window would submit the previous workspace's rule id. Not a
  // cross-tenant write (the backend re-derives the rule's own workspace_id
  // and enforce_workspace_role on it, not the client's active workspace),
  // but stale rows and a rule id going stale under the reader's cursor is a
  // real correctness bug on its own.
  const [rules, stats] = isRefreshing ? [null, null] : (data ?? [null, null]);

  // "No false-positive rules learned yet" claims nothing in this workspace is
  // being auto-suppressed. A read that failed claims nothing at all, and on
  // this surface the difference decides whether an operator goes looking for
  // findings that a rule is quietly swallowing. Per AGENTS.md 1.4 the two get
  // separate renderings.
  //
  // `useAsyncData` retains the last good data across a refetch, so `rules !==
  // null` below is exactly "the request has succeeded at least once", which is
  // what licenses the empty state. `status === "success"` alone would blank
  // the rows on every background refresh, and `status === "error"` alone
  // cannot separate a first-load failure from a failed refresh over rows that
  // are still on screen and still worth showing.
  const loadFailed = status === "error" && rules === null;

  // The workspace list failing is worth surfacing on its own: without it an
  // empty picker reads as "this deployment has no workspaces". A failed first
  // load of the rules themselves is left out here because it gets its own
  // ErrorState with a retry below, and would otherwise be stated twice.
  const error =
    mutationError ?? (loadFailed ? null : loadError?.message) ?? workspacesError?.message ?? null;

  // Returns whether the mutation actually landed, so a caller holding a
  // confirmation dialog open can keep it open on failure rather than closing
  // it over an unchanged row, which reads as success.
  async function mutate(action: () => Promise<unknown>, failureMessage: string): Promise<boolean> {
    if (!workspaceId) return false;
    setMutationError(null);
    try {
      await action();
      refetch();
      return true;
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : failureMessage);
      return false;
    }
  }


  const toggleActive = (rule: FalsePositiveRule) =>
    mutate(() => api.setFpRuleActive(rule.id, !rule.active), "failed to update rule");

  // Widen and delete both change what is auto-suppressed across the whole
  // workspace and neither can be undone from this page: widening discards the
  // rule's file scope (there is no "narrow it back" action), and delete is
  // permanent. Both used to fire on a single click.
  const [pending, setPending] = useState<{ rule: FalsePositiveRule; action: "widen" | "delete" } | null>(null);
  const [busy, setBusy] = useState(false);

  async function confirmPending() {
    if (!pending) return;
    setBusy(true);
    try {
      const ok =
        pending.action === "widen"
          ? await mutate(() => api.widenFpRule(pending.rule.id), "failed to widen rule")
          : await mutate(() => api.deleteFpRule(pending.rule.id), "failed to delete rule");
      if (ok) setPending(null);
    } finally {
      setBusy(false);
    }
  }

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
                Learned automatically when a finding is marked &quot;False Positive&quot;; matches (same rule +
                tool, same filename) are auto-suppressed on future scans anywhere in this workspace, including a
                different repo. Expire a rule to stop it firing, widen it to match any file, or delete it entirely.
              </div>
            </div>
          </div>

          {workspaceId == null && (
            <EmptyState
              icon={Building2}
              title="Pick a workspace"
              description="False-positive rules are per-workspace; choose one from the switcher in the sidebar to view them."
              bare
            />
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

          {workspaceId != null && loadFailed && (
            <ErrorState
              title="Couldn't load false-positive rules"
              description={loadError?.message}
              onRetry={refetch}
            />
          )}

          {workspaceId != null && !loadFailed && (
            <div className="flex flex-col divide-y divide-border rounded-md border border-border">
              {rules === null ? (
                <div className="px-3 py-2">
                  <SkeletonList count={2} />
                </div>
              ) : rules.length === 0 ? (
                <EmptyState
                  icon={ShieldOff}
                  title="No false-positive rules learned yet"
                  description={'For this workspace, triage a finding as "False Positive" to teach one.'}
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
                          onClick={() => setPending({ rule: r, action: "widen" })}
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
                        onClick={() => setPending({ rule: r, action: "delete" })}
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

          {/* Widen is the subtle one: it is not a delete, but it broadens
              automatic suppression from one filename to every file in the
              workspace for that rule + tool. How many findings that newly
              suppresses is not something this page can know, so the dialog
              states the new match scope exactly rather than guessing a count. */}
          <ConfirmDialog
            open={pending !== null}
            title={
              pending?.action === "widen" ? "Widen this rule to every file?" : "Delete this false-positive rule?"
            }
            description={
              pending?.action === "widen" ? (
                <>
                  <strong>{pending.rule.rule_id}</strong> ({pending.rule.tool}) currently auto-suppresses only findings
                  in files named <strong>{pending.rule.file_path_pattern}</strong>. Widening makes it suppress that
                  rule in <strong>every file in this workspace</strong>, on every future scan, including repos it has
                  never matched. There is no narrow-it-back action &mdash; you would have to delete the rule and
                  re-triage a finding to relearn it.
                </>
              ) : (
                <>
                  <strong>{pending?.rule.rule_id}</strong> ({pending?.rule.tool}) is removed permanently. Findings it
                  was suppressing will start appearing in scan results again. To stop auto-suppressing without losing
                  the rule, expire it instead.
                  {pending ? (
                    <span className="mt-2 block">
                      It has matched {pending.rule.match_count} finding{pending.rule.match_count === 1 ? "" : "s"} so
                      far.
                    </span>
                  ) : null}
                </>
              )
            }
            confirmLabel={pending?.action === "widen" ? "Widen rule" : "Delete rule"}
            tone="destructive"
            loading={busy}
            onConfirm={confirmPending}
            onCancel={() => setPending(null)}
          />
        </CardContent>
      </Card>
    </div>
  );
}
