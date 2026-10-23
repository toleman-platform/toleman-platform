"use client";

import { useState } from "react";

/**
 * Reset target selection during the same render as a workspace change; hiding
 * out-of-scope options does not clear IDs used by reads/actions/exports. Preserve
 * allTargetsValue because it re-scopes naturally. Null means untouched/default; []
 * means explicitly cleared. Callers must use selection ?? default so Clear cannot
 * silently reselect a target.
 */
export function useWorkspaceScopedSelection(
  activeWorkspaceId: number | null,
  allTargetsValue?: number,
  initial: number[] | null | (() => number[] | null) = null,
): [number[] | null, (ids: number[]) => void] {
  const [ids, setIds] = useState<number[] | null>(initial);
  const [lastWorkspaceId, setLastWorkspaceId] = useState(activeWorkspaceId);
  if (lastWorkspaceId !== activeWorkspaceId) {
    setLastWorkspaceId(activeWorkspaceId);
    // A workspace switch resets back to "nothing explicitly chosen" (not to
    // `[]`): the point is to let each page's default apply to the *new*
    // workspace, not to freeze the picker cleared forever.
    if (allTargetsValue === undefined || !(ids ?? []).includes(allTargetsValue)) {
      setIds(null);
    }
  }
  return [ids, setIds];
}
