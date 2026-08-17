"use client";

import { useCallback, useMemo, useState } from "react";
import { api, WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "./use-async-data";

/**
 * The "load workspaces, default to the first one, scope everything below to
 * it" preamble (issue #210).
 *
 * Seven admin panels wrote this by hand and each got a slightly different
 * result. The differences were not cosmetic:
 *
 *   - Most dropped the `api.workspaces()` rejection on the floor entirely --
 *     no `.catch`, so a failed load left the panel in a permanent empty state
 *     that was indistinguishable from "this deployment has no workspaces".
 *     Every one of those panels then rendered an empty list as fact.
 *   - The selection was seeded inside a `.then`, so any refetch that happened
 *     to land later could reset the user's choice back to the first workspace.
 *
 * This hook derives the default instead of writing it, so a reload can never
 * yank the user somewhere they did not ask to be, and there is no effect to
 * get the ordering wrong in.
 */
export type UseWorkspacePickerResult = {
  workspaces: WorkspaceSummary[] | null;
  workspaceId: number | null;
  setWorkspaceId: (id: number | null) => void;
  /** True until the workspace list itself has resolved. Distinct from the
   * scoped fetch that hangs off `workspaceId`. */
  isLoading: boolean;
  /** Non-null when the workspace list failed. Callers must surface it: an
   * empty picker is otherwise read as "no workspaces exist". */
  error: Error | null;
  reload: () => void;
};

export function useWorkspacePicker(): UseWorkspacePickerResult {
  const { data, error, isInitialLoading, refetch } = useAsyncData<WorkspaceSummary[]>(
    () => api.workspaces(),
  );
  const [chosen, setChosen] = useState<number | null>(null);

  // Derived, not written in an effect. An effect that seeds state from data
  // costs an extra render, is what `react-hooks/set-state-in-effect` flags,
  // and has to be guarded against clobbering a later user choice. Falling
  // through to the first workspace expresses "user choice wins" directly:
  // once `chosen` is set, the list can reload freely without moving anyone.
  const workspaceId = chosen ?? data?.[0]?.id ?? null;

  const select = useCallback((id: number | null) => setChosen(id), []);

  return useMemo(
    () => ({
      workspaces: data,
      workspaceId,
      setWorkspaceId: select,
      isLoading: isInitialLoading,
      error,
      reload: refetch,
    }),
    [data, workspaceId, select, isInitialLoading, error, refetch],
  );
}
