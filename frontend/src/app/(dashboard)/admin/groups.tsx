"use client";

import { useEffect, useState } from "react";
import { api, EnforcementMode, Group, WorkspaceSummary, workspaceDisplayName } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { EnforcementModeSelect } from "@/components/enforcement-mode-select";
import { Building2, FolderTree, Tag, Trash2 } from "lucide-react";

const SWATCHES = ["#e11d48", "#ea580c", "#ca8a04", "#16a34a", "#0891b2", "#2563eb", "#7c3aed", "#c026d3"];

// Issue #61: workspace-scoped tags/groups ("production", "PCI-scope",
// "internal-tool", ...) for organizing Targets at scale -- foundation for
// group-level policy (#62) and group-level SLA (#70). Mirrors the
// Policies tab's workspace-picker-then-CRUD-list shape.
export function Groups() {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[] | null>(null);
  const [workspaceId, setWorkspaceId] = useState<number | null>(null);
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [color, setColor] = useState(SWATCHES[0]);
  const [saving, setSaving] = useState(false);
  const [wsEnforcementBusy, setWsEnforcementBusy] = useState(false);

  useEffect(() => {
    api.workspaces().then((list) => {
      setWorkspaces(list);
      if (list.length > 0) setWorkspaceId(list[0].id);
    });
  }, []);

  const activeWorkspace = workspaces?.find((w) => w.id === workspaceId) ?? null;

  async function changeWorkspaceEnforcement(mode: EnforcementMode | null) {
    if (!workspaceId) return;
    setWsEnforcementBusy(true);
    setError(null);
    try {
      const updated = await api.updateWorkspace(workspaceId, { enforcement_mode: mode });
      setWorkspaces((prev) => (prev ? prev.map((w) => (w.id === updated.id ? updated : w)) : prev));
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to update workspace enforcement mode");
    } finally {
      setWsEnforcementBusy(false);
    }
  }

  async function changeGroupEnforcement(groupId: number, mode: EnforcementMode | null) {
    if (!workspaceId) return;
    setError(null);
    try {
      const updated = await api.updateGroup(groupId, { enforcement_mode: mode });
      setGroups((prev) => (prev ? prev.map((g) => (g.id === updated.id ? updated : g)) : prev));
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to update group enforcement mode");
    }
  }

  function refresh(wsId: number) {
    setLoading(true);
    api
      .groups(wsId)
      .then(setGroups)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load groups"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (workspaceId != null) refresh(workspaceId);
  }, [workspaceId]);

  async function createGroup() {
    if (!workspaceId || !name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await api.createGroup({ workspace_id: workspaceId, name: name.trim(), color });
      setName("");
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create group");
    } finally {
      setSaving(false);
    }
  }

  async function removeGroup(id: number) {
    if (!workspaceId) return;
    try {
      await api.deleteGroup(id);
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete group");
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
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/40 px-3 py-2">
              <span className="text-xs text-muted-foreground">
                Workspace-level PR Guardrail enforcement (fallback when a target and its groups have none set):
              </span>
              <EnforcementModeSelect
                value={activeWorkspace.enforcement_mode}
                onChange={changeWorkspaceEnforcement}
                disabled={wsEnforcementBusy}
                inheritLabel="Default (Block)"
              />
            </div>
          )}

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
                        <EnforcementModeSelect
                          value={g.enforcement_mode}
                          onChange={(mode) => changeGroupEnforcement(g.id, mode)}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="shrink-0 text-muted-foreground hover:text-destructive"
                          onClick={() => removeGroup(g.id)}
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
