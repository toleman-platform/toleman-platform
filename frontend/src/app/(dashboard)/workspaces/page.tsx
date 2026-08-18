"use client";

import { useState } from "react";
import { Building2, Check, Pencil, X } from "lucide-react";
import { api, workspaceDisplayName } from "@/lib/api";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { WorkspaceKeyCard } from "./workspace-key-card";
import { WorkspaceRoles } from "../admin/workspace-roles";

// Issue #224: workspaces previously had no dedicated management surface at
// all -- the only ways to reach one were the per-workspace API key buried
// behind a target picker in Settings, and role assignment buried as one of
// eleven flat tabs in Admin. This page is the one place to see every
// workspace this user can access, rename it, and manage its API key and
// role assignments -- absorbing the old "Workspace Roles" admin tab.
function RenamableWorkspaceRow({
  workspace,
  displayName,
  selected,
  onSelect,
  onRenamed,
}: {
  workspace: { id: number; name: string };
  displayName: string;
  selected: boolean;
  onSelect: () => void;
  onRenamed: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(workspace.name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    const trimmed = draft.trim();
    if (!trimmed || trimmed === workspace.name) {
      setEditing(false);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await api.updateWorkspace(workspace.id, { name: trimmed });
      onRenamed();
      setEditing(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to rename workspace");
    } finally {
      setSaving(false);
    }
  }

  if (editing) {
    return (
      <div className="flex items-center gap-2 px-3 py-2">
        <Input
          autoFocus
          className="h-8 bg-secondary"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") save();
            if (e.key === "Escape") setEditing(false);
          }}
        />
        <Button size="icon" variant="outline" className="h-8 w-8 shrink-0" disabled={saving} onClick={save} aria-label="Save name">
          <Check className="h-4 w-4" />
        </Button>
        <Button
          size="icon"
          variant="outline"
          className="h-8 w-8 shrink-0"
          disabled={saving}
          onClick={() => {
            setDraft(workspace.name);
            setEditing(false);
          }}
          aria-label="Cancel rename"
        >
          <X className="h-4 w-4" />
        </Button>
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>
    );
  }

  return (
    <button
      onClick={onSelect}
      className={cn(
        "flex w-full items-center justify-between gap-3 px-3 py-2 text-left transition-colors",
        selected ? "bg-accent" : "hover:bg-secondary/50"
      )}
    >
      <div className="min-w-0">
        <div className={cn("truncate text-sm font-medium", selected ? "text-accent-strong" : "text-foreground")}>
          {displayName}
        </div>
        <div className="text-xs text-muted-foreground">Workspace #{workspace.id}</div>
      </div>
      <Pencil
        className="h-3.5 w-3.5 shrink-0 text-muted-foreground hover:text-foreground"
        onClick={(e) => {
          e.stopPropagation();
          setEditing(true);
        }}
      />
    </button>
  );
}

export default function WorkspacesPage() {
  const { workspaces, workspaceId, setWorkspaceId, isLoading, error, reload } = useWorkspacePicker();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Workspaces</h1>
        <p className="text-sm text-muted-foreground">
          Rename a workspace, manage its CI-ingestion API key, and assign per-workspace roles.
        </p>
      </div>

      {error && <p className="text-xs text-destructive">{error.message}</p>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[280px_1fr]">
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col divide-y divide-border px-0 py-0">
            {isLoading ? (
              <div className="px-3 py-2">
                <SkeletonList count={3} />
              </div>
            ) : !workspaces || workspaces.length === 0 ? (
              <EmptyState
                icon={Building2}
                title="No workspaces yet"
                description="Connect a target first to create a workspace."
                bare
              />
            ) : (
              workspaces.map((w) => (
                <RenamableWorkspaceRow
                  key={w.id}
                  workspace={w}
                  displayName={workspaceDisplayName(w, workspaces)}
                  selected={w.id === workspaceId}
                  onSelect={() => setWorkspaceId(w.id)}
                  onRenamed={reload}
                />
              ))
            )}
          </CardContent>
        </Card>

        {workspaceId !== null ? (
          <div className="flex flex-col gap-6">
            <WorkspaceKeyCard key={workspaceId} workspaceId={workspaceId} />
            <WorkspaceRoles workspaceId={workspaceId} />
          </div>
        ) : (
          !isLoading && (
            <div className="flex items-center justify-center text-sm text-muted-foreground">
              Select a workspace to manage it.
            </div>
          )
        )}
      </div>
    </div>
  );
}
