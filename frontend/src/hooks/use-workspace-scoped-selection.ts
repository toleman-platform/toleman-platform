"use client";

import { useState } from "react";

/**
 * A repo-picker selection (`number[]`) that resets when the active workspace
 * changes.
 *
 * A specific target id belongs to whichever workspace was active when it was
 * picked; switching the global workspace switcher must not leave that (now
 * likely out-of-scope) id selected underneath a freshly-scoped repo list --
 * `TargetPicker` only hides ids absent from its current `targets` prop, it
 * does not drop them from the selection it is handed, so every read/action/
 * export keyed off that state would otherwise keep reaching a target that
 * belongs to a workspace the reader has since switched away from. The
 * backend authorizes each target against its own workspace, not the
 * caller's *currently active* one, so a stale id is not merely a display
 * glitch: a developer with access to two workspaces could still read or
 * write a target in the one they just switched off of (#519 review).
 *
 * `allTargetsValue` (e.g. `ALL_TARGETS`) is exempt from the reset when
 * given: an org-wide selection re-scopes cleanly to the new workspace on
 * its own, and a switch should not kick the reader out of it.
 *
 * React's documented "adjust state when a prop changes" pattern, not an
 * effect, so the reset lands the same render the switch does (see
 * sidebar.tsx's `lastPathname`) -- this was previously duplicated inline in
 * sbom/page.tsx; every other page carrying a workspace-scoped selection
 * should use this instead of re-deriving it.
 */
export function useWorkspaceScopedSelection(
  activeWorkspaceId: number | null,
  allTargetsValue?: number,
  initial: number[] | (() => number[]) = [],
): [number[], (ids: number[]) => void] {
  const [ids, setIds] = useState<number[]>(initial);
  const [lastWorkspaceId, setLastWorkspaceId] = useState(activeWorkspaceId);
  if (lastWorkspaceId !== activeWorkspaceId) {
    setLastWorkspaceId(activeWorkspaceId);
    if (allTargetsValue === undefined || !ids.includes(allTargetsValue)) {
      setIds([]);
    }
  }
  return [ids, setIds];
}
