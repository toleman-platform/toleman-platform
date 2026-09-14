"use client";

import { useState } from "react";
import { api, EnforcementMode, Group, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import {
  ENFORCEMENT_MODE_HELP,
  EnforcementModeLabel,
  EnforcementModeSelect,
  resolveEnforcementMode,
} from "@/components/features/targets";
import { Building2, FolderTree, Tag, Trash2 } from "lucide-react";

const SWATCHES = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--accent-strong)",
  "var(--destructive)",
  "var(--warning)",
];

// Issue #61: workspace-scoped tags/groups ("production", "PCI-scope",
// "internal-tool", ...) for organizing Targets at scale, foundation for
// group-level policy (#62) and group-level SLA (#70). Mirrors the
// Policies tab's workspace-picker-then-CRUD-list shape.
export function Groups() {
  const {
    workspaces,
    workspaceId,
    setWorkspaceId,
    error: workspacesError,
    reload: reloadWorkspaces,
  } = useWorkspacePicker();
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data: groups,
    error: loadError,
    isInitialLoading: loading,
    refetch,
  } = useAsyncData<Group[]>(() => api.groups(workspaceId!), {
    enabled: workspaceId != null,
    deps: [workspaceId],
  });

  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  const [name, setName] = useState("");
  const [color, setColor] = useState(SWATCHES[0]);
  const [saving, setSaving] = useState(false);
  const [wsEnforcementBusy, setWsEnforcementBusy] = useState(false);

  const activeWorkspace = workspaces?.find((w) => w.id === workspaceId) ?? null;

  // The mode every group and target in this workspace falls back to when it
  // sets no override of its own. Needed to render what "Inherit" resolves to.
  const workspaceEffectiveMode = resolveEnforcementMode(activeWorkspace?.enforcement_mode ?? null, null);

  // Changing the workspace select used to apply on `onChange` with no
  // confirmation and no undo. Going from Block to Alert or Disabled stops PR
  // Guardrail blocking merges across every repo in the workspace that has no
  // override of its own, which is a security-posture downgrade for the whole
  // workspace made by one keystroke on a combobox.
  const [pendingWsMode, setPendingWsMode] = useState<{ next: EnforcementMode | null } | null>(null);

  function requestWorkspaceEnforcement(mode: EnforcementMode | null) {
    const current = workspaceEffectiveMode;
    const next = resolveEnforcementMode(mode, null);
    if (next === current) {
      // Same effective outcome (e.g. explicit "block" -> "Default (Block)");
      // nothing is being weakened, so don't manufacture a scary dialog.
      changeWorkspaceEnforcement(mode);
      return;
    }
    // Only a *downgrade* is gated. block is strictest, then alert, then
    // disabled; tightening enforcement needs no warning.
    const strictness: Record<EnforcementMode, number> = { block: 2, alert: 1, disabled: 0 };
    if (strictness[next] < strictness[current]) {
      setPendingWsMode({ next: mode });
      return;
    }
    changeWorkspaceEnforcement(mode);
  }

  async function changeWorkspaceEnforcement(mode: EnforcementMode | null) {
    if (!workspaceId) return;
    setWsEnforcementBusy(true);
    setMutationError(null);
    try {
      await api.updateWorkspace(workspaceId, { enforcement_mode: mode });
      // Refetch rather than patching the row in place: the workspace list is
      // owned by useWorkspacePicker, and a second source of truth for it is
      // how these panels drifted apart in the first place.
      reloadWorkspaces();
      setPendingWsMode(null);
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to update workspace enforcement mode");
    } finally {
      setWsEnforcementBusy(false);
    }
  }

  async function changeGroupEnforcement(groupId: number, mode: EnforcementMode | null) {
    if (!workspaceId) return;
    setMutationError(null);
    try {
      await api.updateGroup(groupId, { enforcement_mode: mode });
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to update group enforcement mode");
    }
  }

  async function createGroup() {
    if (!workspaceId || !name.trim()) return;
    setSaving(true);
    setMutationError(null);
    try {
      await api.createGroup({ workspace_id: workspaceId, name: name.trim(), color });
      setName("");
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to create group");
    } finally {
      setSaving(false);
    }
  }

  // Deleting a group is not just untagging targets: the group carries
  // group-scoped SLA rules (#70) and a group-level enforcement override
  // (#62), and both go with it. None of that was stated anywhere, and the
  // trash button mutated on click.
  const [pendingDelete, setPendingDelete] = useState<Group | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function removeGroup(id: number) {
    if (!workspaceId) return;
    setDeleting(true);
    try {
      await api.deleteGroup(id);
      setPendingDelete(null);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to delete group");
    } finally {
      setDeleting(false);
    }
  }


  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <Tag className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Repo Groups</div>
              <div className="text-xs text-muted-foreground">
                Tag targets (e.g. &quot;production&quot;, &quot;PCI-scope&quot;, &quot;internal-tool&quot;) to organize at
                scale. Assign groups to a target from its detail page; filter targets and findings by group
                from their list views.
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

          {activeWorkspace && (
            <div className="flex flex-col gap-2 rounded-md border border-border bg-secondary/40 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  Workspace-level PR Guardrail enforcement (fallback when a target and its groups have none set):
                </span>
                <EnforcementModeSelect
                  value={activeWorkspace.enforcement_mode}
                  onChange={requestWorkspaceEnforcement}
                  disabled={wsEnforcementBusy}
                  inheritLabel="Default (Block)"
                  label="Workspace enforcement mode"
                />
                <EnforcementModeLabel
                  mode={workspaceEffectiveMode}
                  source={activeWorkspace.enforcement_mode ? undefined : "default"}
                />
              </div>
              {/* What the three options mean, at the point they are chosen.
                  They were bare one-word labels with the explanation nowhere
                  in the UI. */}
              <dl className="flex flex-col gap-0.5 text-xs text-muted-foreground">
                <div>
                  <dt className="inline font-medium text-foreground">Block</dt>{" "}
                  <dd className="inline">{ENFORCEMENT_MODE_HELP.block}</dd>
                </div>
                <div>
                  <dt className="inline font-medium text-foreground">Alert</dt>{" "}
                  <dd className="inline">{ENFORCEMENT_MODE_HELP.alert}</dd>
                </div>
                <div>
                  <dt className="inline font-medium text-foreground">Disabled</dt>{" "}
                  <dd className="inline">{ENFORCEMENT_MODE_HELP.disabled}</dd>
                </div>
              </dl>
            </div>
          )}

          {/* The count of affected repos is deliberately not asserted here:
              this page has no target inventory to count from, and a made-up
              number on a security-posture warning is worse than none. The
              scope is stated exactly instead. */}
          <ConfirmDialog
            open={pendingWsMode !== null}
            title="Weaken PR Guardrail for this whole workspace?"
            description={
              <>
                Every target in <strong>{activeWorkspace ? workspaceDisplayName(activeWorkspace, workspaces ?? []) : "this workspace"}</strong>{" "}
                that doesn&apos;t set its own enforcement mode, directly or through a group, changes from{" "}
                <strong>{workspaceEffectiveMode}</strong> to{" "}
                <strong>{resolveEnforcementMode(pendingWsMode?.next ?? null, null)}</strong> immediately.{" "}
                {ENFORCEMENT_MODE_HELP[resolveEnforcementMode(pendingWsMode?.next ?? null, null)]}
              </>
            }
            confirmLabel="Change enforcement mode"
            tone="destructive"
            loading={wsEnforcementBusy}
            onConfirm={() => pendingWsMode && changeWorkspaceEnforcement(pendingWsMode.next)}
            onCancel={() => setPendingWsMode(null)}
          />

          {workspaceId != null && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  className="w-56 bg-secondary"
                  placeholder="Group name (e.g. production)"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <div className="flex items-center gap-1">
                  {SWATCHES.map((s) => (
                    <button
                      key={s}
                      type="button"
                      aria-label={`Color ${s}`}
                      onClick={() => setColor(s)}
                      className="h-6 w-6 rounded-full ring-offset-2 ring-offset-background transition-shadow"
                      style={{ backgroundColor: s, boxShadow: color === s ? `0 0 0 2px ${s}` : "none" }}
                    />
                  ))}
                </div>
                <Button onClick={createGroup} disabled={saving || !name.trim()} className="shrink-0">
                  {saving ? "Adding..." : "Add group"}
                </Button>
              </div>

              {error && <p className="text-xs text-destructive">{error}</p>}

              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                {loading ? (
                  <div className="px-3 py-2">
                    <SkeletonList count={2} />
                  </div>
                ) : !groups || groups.length === 0 ? (
                  <EmptyState
                    icon={FolderTree}
                    title="No groups yet"
                    description="For this workspace."
                    bare
                  />
                ) : (
                  groups.map((g) => (
                    <div key={g.id} className="flex items-center justify-between gap-3 px-3 py-2">
                      <span
                        className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium text-white"
                        style={{ backgroundColor: g.color }}
                      >
                        {g.name}
                      </span>
                      <div className="flex items-center gap-2">
                        {/* "Inherit" alone doesn't say what it resolves to, so
                            the group → workspace half of the chain was legible
                            on target detail and illegible on the page where it
                            is actually changed. */}
                        <EnforcementModeSelect
                          value={g.enforcement_mode}
                          onChange={(mode) => changeGroupEnforcement(g.id, mode)}
                          inheritLabel={`Inherit (${workspaceEffectiveMode})`}
                          label={`Enforcement mode for group ${g.name}`}
                        />
                        <EnforcementModeLabel
                          mode={resolveEnforcementMode(g.enforcement_mode, activeWorkspace?.enforcement_mode ?? null)}
                          source={g.enforcement_mode ? undefined : activeWorkspace?.enforcement_mode ? "workspace" : "default"}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="shrink-0 text-muted-foreground hover:text-destructive"
                          onClick={() => setPendingDelete(g)}
                          aria-label={`Delete group ${g.name}`}
                          title={`Delete group ${g.name}`}
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
                title={`Delete group "${pendingDelete?.name ?? ""}"?`}
                description={
                  <>
                    The group&apos;s SLA rules and its enforcement-mode override are deleted with it. Targets tagged
                    with it lose the tag and fall back to the workspace defaults. This can&apos;t be undone.
                  </>
                }
                confirmLabel="Delete group"
                tone="destructive"
                loading={deleting}
                onConfirm={() => pendingDelete && removeGroup(pendingDelete.id)}
                onCancel={() => setPendingDelete(null)}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
