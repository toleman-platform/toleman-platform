"use client";

import { useCallback, useMemo, useState } from "react";
import { api, type WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";

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
};

export function useWorkspacePicker(): UseWorkspacePickerResult {
  const { data, error, isInitialLoading, refetch } = useAsyncData<WorkspaceSummary[]>(
    () => api.workspaces(),
  );
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
    }),
    [data, error, isInitialLoading, refetch, select, workspaceId],
  );
}
