"use client";

import { useEffect, useState } from "react";
import { api, Group, GroupBadge as GroupBadgeType } from "@/lib/api";
import { GroupBadge } from "@/components/group-badge";
import { Button } from "@/components/ui/button";

// Issue #61: assign/remove this target's groups from its detail page. Only
// offers groups that already exist in this target's workspace (created via
// Admin > Repo Groups), matches the backend's same-workspace check on
// POST /api/targets/{id}/groups/{group_id}.
export function TargetGroups({ targetId, workspaceId }: { targetId: number; workspaceId: number }) {
  const [assigned, setAssigned] = useState<GroupBadgeType[] | null>(null);
  const [available, setAvailable] = useState<Group[] | null>(null);
  const [selected, setSelected] = useState<number | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    api.targetGroups(targetId).then(setAssigned).catch(() => setAssigned([]));
  }

  useEffect(() => {
    refresh();
    api.groups(workspaceId).then(setAvailable).catch(() => setAvailable([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId, workspaceId]);

  const assignedIds = new Set((assigned ?? []).map((g) => g.id));
  const unassigned = (available ?? []).filter((g) => !assignedIds.has(g.id));

  async function addGroup() {
    if (selected === "") return;
    setBusy(true);
    setError(null);
    try {
      await api.assignTargetGroup(targetId, Number(selected));
      setSelected("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to assign group");
    } finally {
      setBusy(false);
    }
  }

  async function removeGroup(groupId: number) {
    setBusy(true);
    setError(null);
    try {
      await api.removeTargetGroup(targetId, groupId);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to remove group");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {assigned === null ? (
          <span className="text-xs text-muted-foreground">Loading groups...</span>
        ) : assigned.length === 0 ? (
          <span className="text-xs text-muted-foreground">No groups assigned.</span>
        ) : (
          assigned.map((g) => (
            <GroupBadge key={g.id} group={g} onRemove={() => removeGroup(g.id)} />
          ))
        )}
      </div>

      {unassigned.length > 0 && (
        <div className="flex items-center gap-2">
          <select
            aria-label="Assign a group"
            className="h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground"
            value={selected}
            onChange={(e) => setSelected(e.target.value === "" ? "" : Number(e.target.value))}
          >
            <option value="">Assign a group...</option>
            {unassigned.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
          <Button size="sm" variant="outline" className="h-8 text-xs" disabled={busy || selected === ""} onClick={addGroup}>
            Add
          </Button>
        </div>
      )}

      {available !== null && available.length === 0 && (
        <span className="text-xs text-muted-foreground">
          No groups exist for this workspace yet, create one in Admin &gt; Repo Groups.
        </span>
      )}

      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
