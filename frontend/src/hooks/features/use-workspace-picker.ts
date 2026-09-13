"use client";

import { useCallback, useMemo, useState } from "react";
import { api, type WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import type { UseAsyncDataResult } from "@/hooks/use-async-data";

/**
 * L3 Domain Hook: Manages workspace selection state across admin panels (issue #210).
 *
 * Automatically resolves the initial workspace ID without race conditions.
 * Preserves user selections across background refetches and handles loading/error states.
 */
export type UseWorkspacePickerResult = {
  workspaces: WorkspaceSummary[] | null;
  workspaceId: number | null;
  setWorkspaceId: (id: number | null) => void;
  isLoading: boolean;
  error: Error | null;
  reload: () => void;
  /** The underlying request, whole, for handing to `<AsyncContent>` (#356).
   * The flattened fields above cover a caller that only needs to decorate a
   * `<select>`; a caller whose whole surface depends on the list wants the
   * full ladder (initial skeleton, error-with-retry, stale-data-plus-retry
   * banner, empty) and should not hand-roll it from `isLoading`/`error`,
   * which is the exact duplication #210 collapsed. */
  state: UseAsyncDataResult<WorkspaceSummary[]>;
};

export function useWorkspacePicker(): UseWorkspacePickerResult {
  const state = useAsyncData<WorkspaceSummary[]>(() => api.workspaces());
  const { data, error, isInitialLoading, refetch } = state;
  const [chosen, setChosen] = useState<number | null>(null);

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
      state,
    }),
    [data, error, isInitialLoading, refetch, select, state, workspaceId],
  );
}
