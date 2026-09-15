"use client";

import { useState } from "react";
import { api, Group, SlaRule, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { SeverityChip } from "@/components/ui/severity-chip";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Building2, Check, Clock, Timer, Trash2, X } from "lucide-react";

// Issue #70: workspace-scoped SLA (days-to-fix) rules, keyed by severity and
// optionally a repo Group (#61); null group means "workspace default",
// applied to targets with no group-specific rule for that severity. Mirrors
// the Groups tab's workspace-picker-then-CRUD-list shape (#61/#62).
// An empty days field parses as `Number("") === 0`, which satisfied the old
// `>= 0` guard and silently created a 0-day SLA -- one that is breached the
// moment it exists. A rule has to mean "you have at least one day".
function isValidDays(raw: string): boolean {
  if (raw.trim() === "") return false;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1;
}

// M16: this used to be a bare `<Input defaultValue={r.days_to_fix} onBlur={...}>`
// that committed to the server the instant the field lost focus -- clicking
// anywhere else on the page (or tabbing to the delete button) saved whatever
// was in the box, half-typed or not, with no confirmation and no way back.
// A day count silently changes every open finding's SLA deadline for this
// severity/group, so "I was still typing" is not a safe thing for a blur
// event to interpret as "save this".
//
// Fixed the same way every other mutation on this page already is: nothing
// reaches the server until an explicit action. Enter or the checkmark
// commits; Escape or the X discards the draft and restores what is actually
// configured. The Save/Discard pair only appears once the draft differs from
// the committed value, so an untouched row stays exactly as quiet as before.
//
// `key`-remounted from the parent (`${rule.id}-${rule.days_to_fix}`, same
// trick as risk-scoring.tsx's SignalRow) rather than synced with an effect:
// a successful save changes `rule.days_to_fix`, which is a fresh committed
// value this component should adopt outright, not diff against.
function SlaDaysEditor({
  rule,
  label,
  onSave,
}: {
  rule: SlaRule;
  /** e.g. "Critical in production" -- disambiguates rows sharing a severity across groups. */
  label: string;
  onSave: (days: number) => Promise<void>;
}) {
  const [draft, setDraft] = useState(String(rule.days_to_fix));
  const [saving, setSaving] = useState(false);
  const dirty = draft !== String(rule.days_to_fix);
  const valid = isValidDays(draft);

  function discard() {
    setDraft(String(rule.days_to_fix));
  }

  async function commit() {
    if (!valid || saving) return;
    setSaving(true);
    try {
      await onSave(Number(draft));
      // No local reset on success: the parent's refetch changes
      // `rule.days_to_fix`, which remounts this row via `key` and adopts the
      // new value as the fresh committed draft.
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex items-center gap-1">
      <Input
        type="number"
        min={1}
        aria-label={`Days to fix for ${label}`}
        className="h-8 w-20 bg-secondary text-xs"
        value={draft}
        disabled={saving}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit();
          else if (e.key === "Escape") discard();
        }}
      />
      <span className="text-xs text-muted-foreground">days</span>
      {dirty && (
        <>
          <Button
            variant="ghost"
            size="icon"
            className="shrink-0 text-muted-foreground hover:text-chart-5 disabled:opacity-40"
            onClick={commit}
            disabled={!valid || saving}
            aria-label={`Save days to fix for ${label}`}
            title={valid ? "Save" : "Days to fix must be a whole number of at least 1"}
          >
            <Check className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="shrink-0 text-muted-foreground hover:text-destructive"
            onClick={discard}
            disabled={saving}
            aria-label={`Discard unsaved days to fix for ${label}`}
            title="Discard change"
          >
            <X className="h-4 w-4" />
          </Button>
        </>
      )}
    </div>
  );
}

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
    if (!isValidDays(days)) {
      setMutationError("Days to fix must be a whole number of at least 1");
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
    // Same floor as `createRule`: a 0-day SLA is breached the instant it's
    // saved, and `isValidDays` is the one place that rule lives. The old
    // `newDays < 0` guard here independently allowed exactly that -- this
    // path did not go through `isValidDays` at all, so the inline editor
    // could create the zero-day SLA the create form was hardened against.
    if (!workspaceId || !isValidDays(String(newDays))) return;
    try {
      await api.updateSlaRule(rule.id, { days_to_fix: newDays });
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to update SLA rule");
    }
  }

  // Deleting an SLA rule silently changes (or removes) the deadline on every
  // finding it governs -- a target with no matching rule anywhere shows no
  // SLA at all. It used to fire on click from an unlabelled icon button.
  const [pendingDelete, setPendingDelete] = useState<SlaRule | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function removeRule(id: number) {
    if (!workspaceId) return;
    setDeleting(true);
    try {
      await api.deleteSlaRule(id);
      setPendingDelete(null);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to delete SLA rule");
    } finally {
      setDeleting(false);
    }
  }

  function groupName(id: number | null): string {
    if (id == null) return "Workspace default";
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

          {workspaceId != null && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Repo group this rule applies to"
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
                  aria-label="Severity this rule applies to"
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
                  min={1}
                  aria-label="Days to fix"
                  className="w-28 bg-secondary"
                  placeholder="Days to fix"
                  value={days}
                  onChange={(e) => setDays(e.target.value)}
                />
                <Button onClick={createRule} disabled={saving || !isValidDays(days)} className="shrink-0">
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
                          <SeverityChip severity={r.severity} size="sm" />
                          <span className="text-xs text-muted-foreground">{groupName(r.group_id)}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <SlaDaysEditor
                            key={`${r.id}-${r.days_to_fix}`}
                            rule={r}
                            label={`${r.severity} in ${groupName(r.group_id)}`}
                            onSave={(newDays) => updateDays(r, newDays)}
                          />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="shrink-0 text-muted-foreground hover:text-destructive"
                            onClick={() => setPendingDelete(r)}
                            aria-label={`Delete SLA rule: ${r.severity} in ${groupName(r.group_id)}`}
                            title="Delete rule"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))
                )}
              </div>

              <ConfirmDialog
                open={pendingDelete !== null}
                title="Delete this SLA rule?"
                description={
                  <>
                    <strong>
                      {pendingDelete ? `${pendingDelete.severity} in ${groupName(pendingDelete.group_id)}` : ""}
                    </strong>{" "}
                    stops governing days-to-fix immediately. Findings it covered fall back to the workspace default
                    for that severity, or show no SLA at all if there isn&apos;t one. This can&apos;t be undone.
                  </>
                }
                confirmLabel="Delete rule"
                tone="destructive"
                loading={deleting}
                onConfirm={() => pendingDelete && removeRule(pendingDelete.id)}
                onCancel={() => setPendingDelete(null)}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
