"use client";

import { useState } from "react";
import { api, Group, SlaRule, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { SEVERITY_COLOR, SEVERITY_ORDER } from "@/lib/severity";
import { Building2, Clock, Timer, Trash2 } from "lucide-react";

// Issue #70: workspace-scoped SLA (days-to-fix) rules, keyed by severity and
// optionally a repo Group (#61); null group means "workspace default",
// applied to targets with no group-specific rule for that severity. Mirrors
// the Groups tab's workspace-picker-then-CRUD-list shape (#61/#62).
export function SlaRules() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data,
    error: loadError,
    isInitialLoading: loading,
    refetch,
  } = useAsyncData<[SlaRule[], Group[]]>(
    () => Promise.all([api.slaRules(workspaceId!), api.groups(workspaceId!)]),
    { enabled: workspaceId != null, deps: [workspaceId] },
  );
  const [rules, groups] = data ?? [null, null];

  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  const [groupId, setGroupId] = useState<number | "">("");
  const [severity, setSeverity] = useState<string>(SEVERITY_ORDER[0]);
  const [days, setDays] = useState<string>("7");
  const [saving, setSaving] = useState(false);

  async function createRule() {
    if (!workspaceId) return;
    const daysNum = Number(days);
    if (!Number.isFinite(daysNum) || daysNum < 0) {
      setMutationError("days_to_fix must be a non-negative number");
      return;
    }
    setSaving(true);
    setMutationError(null);
    try {
      await api.createSlaRule({
        workspace_id: workspaceId,
        group_id: groupId === "" ? null : Number(groupId),
        severity,
        days_to_fix: daysNum,
      });
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to create SLA rule (a rule for this group + severity may already exist)");
    } finally {
      setSaving(false);
    }
  }

  async function updateDays(rule: SlaRule, newDays: number) {
    if (!workspaceId || !Number.isFinite(newDays) || newDays < 0) return;
    try {
      await api.updateSlaRule(rule.id, { days_to_fix: newDays });
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to update SLA rule");
    }
  }

  async function removeRule(id: number) {
    if (!workspaceId) return;
    try {
      await api.deleteSlaRule(id);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to delete SLA rule");
    }
  }

  function groupName(id: number | null): string {
    if (id === null) return "Workspace default";
    return groups?.find((g) => g.id === id)?.name ?? `group #${id}`;
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <Timer className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">SLA Rules</div>
              <div className="text-xs text-muted-foreground">
                Days-to-fix per severity, optionally scoped to a repo group (e.g. Critical in
                &quot;production&quot; = 7 days, Medium in &quot;dev&quot; = 30 days). A group rule wins over
                the workspace default; a target with no matching rule anywhere shows no SLA at all.
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

          {workspaceId != null && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                  value={groupId}
                  onChange={(e) => setGroupId(e.target.value === "" ? "" : Number(e.target.value))}
                >
                  <option value="">Workspace default (no group)</option>
                  {groups?.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
                <select
                  className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  {SEVERITY_ORDER.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <Input
                  type="number"
                  min={0}
                  className="w-28 bg-secondary"
                  placeholder="Days to fix"
                  value={days}
                  onChange={(e) => setDays(e.target.value)}
                />
                <Button onClick={createRule} disabled={saving} className="shrink-0">
                  {saving ? "Adding..." : "Add rule"}
                </Button>
              </div>

              {error && <p className="text-xs text-destructive">{error}</p>}

              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                {loading ? (
                  <div className="px-3 py-2">
                    <SkeletonList count={2} />
                  </div>
                ) : !rules || rules.length === 0 ? (
                  <EmptyState
                    icon={Clock}
                    title="No SLA rules yet"
                    description="For this workspace."
                    bare
                  />
                ) : (
                  rules
                    .slice()
                    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
                    .map((r) => (
                      <div key={r.id} className="flex items-center justify-between gap-3 px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${SEVERITY_COLOR[r.severity]}`}
                          >
                            {r.severity}
                          </span>
                          <span className="text-xs text-muted-foreground">{groupName(r.group_id)}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Input
                            type="number"
                            min={0}
                            className="h-8 w-20 bg-secondary text-xs"
                            defaultValue={r.days_to_fix}
                            onBlur={(e) => {
                              const v = Number(e.target.value);
                              if (v !== r.days_to_fix) updateDays(r, v);
                            }}
                          />
                          <span className="text-xs text-muted-foreground">days</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="shrink-0 text-muted-foreground hover:text-destructive"
                            onClick={() => removeRule(r.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
