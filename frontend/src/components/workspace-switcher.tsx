"use client";

/**
 * Issue #506: the global workspace switcher, sitting in the sidebar header
 * next to GlobalSearch. A native `<select>`, matching this codebase's
 * no-component-library convention for form controls (see components/ui --
 * there is no Radix/shadcn Select here).
 */

import { Building2, ChevronDown } from "lucide-react";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { workspaceDisplayName } from "@/lib/api";
import { cn } from "@/lib/utils";

const ALL_WORKSPACES_VALUE = "__all__";

export function WorkspaceSwitcher({ collapsed }: { collapsed?: boolean }) {
  const { workspaces, activeWorkspaceId, setActiveWorkspaceId, isLoading } = useWorkspaceContext();

  // Nothing to switch between yet (still loading, or the org genuinely has
  // zero workspaces this caller can see) -- render nothing rather than a
  // disabled control with only "All workspaces" in it.
  if (isLoading || !workspaces || workspaces.length === 0) return null;

  // workspaceDisplayName disambiguates same-named workspaces across
  // different organisations (e.g. two orgs both called "default") with a
  // `(#id)` suffix, matching every other workspace picker on this platform.
  const activeWorkspace = workspaces.find((w) => w.id === activeWorkspaceId) ?? null;
  const activeLabel = activeWorkspace ? workspaceDisplayName(activeWorkspace, workspaces) : "All workspaces";

  return (
    <div
      className={cn(
        "relative flex items-center gap-2 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-1.5 text-xs text-muted-foreground",
        collapsed ? "w-auto justify-center px-2" : "w-full"
      )}
      title={collapsed ? activeLabel : undefined}
    >
      <Building2 className="h-3.5 w-3.5 shrink-0" />
      {!collapsed && (
        <>
          <span className="flex-1 truncate text-left text-sidebar-foreground">{activeLabel}</span>
          <ChevronDown className="h-3 w-3 shrink-0" />
        </>
      )}
      <select
        aria-label="Active workspace"
        value={activeWorkspaceId === null ? ALL_WORKSPACES_VALUE : String(activeWorkspaceId)}
        onChange={(e) => {
          const value = e.target.value;
          setActiveWorkspaceId(value === ALL_WORKSPACES_VALUE ? null : Number(value));
        }}
        className={cn(
          "absolute inset-0 cursor-pointer appearance-none opacity-0",
        )}
      >
        <option value={ALL_WORKSPACES_VALUE}>All workspaces</option>
        {workspaces.map((w) => (
          <option key={w.id} value={w.id}>
            {workspaceDisplayName(w, workspaces)}
          </option>
        ))}
      </select>
    </div>
  );
}
