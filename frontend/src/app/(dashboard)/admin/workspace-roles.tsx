"use client";

import { useEffect, useState } from "react";
import { api, AuthUser, WorkspaceMembership, WorkspaceRole, WorkspaceSummary, workspaceDisplayName } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Building2, Trash2, UserCog } from "lucide-react";

const WORKSPACE_ROLES: WorkspaceRole[] = ["viewer", "developer", "security_engineer"];

// Issue #32: per-workspace role assignment layered on top of the global
// admin/user/viewer role in user-management.tsx above -- this tab is what
// determines a non-admin's permissions *within* a specific workspace
// (targets, findings, PR guardrail, SBOM, discovery). A global admin can
// still manage everything everywhere regardless of what's assigned here.
export function WorkspaceRoles() {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[] | null>(null);
  const [users, setUsers] = useState<AuthUser[] | null>(null);
  const [workspaceId, setWorkspaceId] = useState<number | null>(null);
  const [memberships, setMemberships] = useState<WorkspaceMembership[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedUserId, setSelectedUserId] = useState<number | "">("");
  const [selectedRole, setSelectedRole] = useState<WorkspaceRole>("developer");
  const [assigning, setAssigning] = useState(false);

  // Issue #118: removing a workspace role assignment is destructive (the
  // user immediately loses that workspace's access) and previously fired
  // straight off the icon-only Trash2 button with no confirmation.
  const [pendingRemoval, setPendingRemoval] = useState<WorkspaceMembership | null>(null);
  const [removing, setRemoving] = useState(false);

  useEffect(() => {
    api.workspaces().then((list) => {
      setWorkspaces(list);
      if (list.length > 0) setWorkspaceId(list[0].id);
    });
    api.users().then(setUsers);
  }, []);

  function refresh(wsId: number) {
    setLoading(true);
    api
      .workspaceMemberships(wsId)
      .then(setMemberships)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load workspace roles"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (workspaceId != null) refresh(workspaceId);
  }, [workspaceId]);

  async function onAssign() {
    if (workspaceId == null || selectedUserId === "") return;
    setAssigning(true);
    setError(null);
    try {
      await api.assignWorkspaceRole(Number(selectedUserId), workspaceId, selectedRole);
      setSelectedUserId("");
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to assign role");
    } finally {
      setAssigning(false);
    }
  }

  async function confirmRemove() {
    if (workspaceId == null || !pendingRemoval) return;
    setRemoving(true);
    try {
      await api.removeWorkspaceMembership(pendingRemoval.id);
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to remove role");
    } finally {
      setRemoving(false);
      setPendingRemoval(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div>
            <div className="font-medium text-foreground">Workspace Roles</div>
            <div className="text-xs text-muted-foreground">
              Grant a user a role scoped to a single workspace. Applies to that workspace&apos;s targets,
              findings, PR guardrail, SBOM, and API discovery. Global admins bypass this and can always
              manage every workspace.
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
            <div className="flex flex-wrap items-end gap-2">
              <select
                className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                value={selectedUserId}
                onChange={(e) => setSelectedUserId(e.target.value === "" ? "" : Number(e.target.value))}
              >
                <option value="">Select user...</option>
                {(users ?? []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.name} ({u.email})
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value as WorkspaceRole)}
              >
                {WORKSPACE_ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <Button onClick={onAssign} disabled={assigning || selectedUserId === ""} className="shrink-0">
                {assigning ? "Assigning..." : "Assign Role"}
              </Button>
            </div>
          )}

          {error && <p className="text-xs text-destructive">{error}</p>}

          <div className="flex flex-col divide-y divide-border rounded-md border border-border">
            {loading ? (
              <div className="px-3 py-2">
                <SkeletonList count={2} />
              </div>
            ) : memberships === null || memberships.length === 0 ? (
              <EmptyState
                icon={UserCog}
                title="No workspace-scoped roles assigned"
                description="For this workspace yet."
                bare
              />
            ) : (
              memberships.map((m) => (
                <div key={m.id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <div>
                    <div className="text-sm font-medium text-foreground">{m.user_name}</div>
                    <div className="text-xs text-muted-foreground">{m.user_email}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{m.role}</Badge>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-destructive"
                      onClick={() => setPendingRemoval(m)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={pendingRemoval !== null}
        title="Remove workspace role"
        description={
          pendingRemoval ? (
            <>
              Remove <span className="font-medium text-foreground">{pendingRemoval.user_name}</span>&apos;s{" "}
              <span className="font-medium text-foreground">{pendingRemoval.role}</span> role on this
              workspace? They&apos;ll immediately lose the access it grants.
            </>
          ) : null
        }
        confirmLabel="Remove"
        tone="destructive"
        loading={removing}
        onConfirm={confirmRemove}
        onCancel={() => setPendingRemoval(null)}
      />
    </div>
  );
}
