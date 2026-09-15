"use client";

/**
 * Issue #506: the one place the platform's active workspace lives.
 *
 * Before this, thirteen pages each ran their own `useWorkspacePicker`
 * (frontend/src/hooks/features/use-workspace-picker.ts) with independent,
 * in-memory-only state, and everything else (Dashboard, Findings, Targets,
 * Scans, ...) had no workspace control at all -- there was no single answer
 * to "which workspace am I looking at". This context is that answer: one
 * fetch of the workspace list, one persisted selection, one value every page
 * reads instead of holding its own.
 *
 * `activeWorkspaceId === null` means "All workspaces" (every workspace the
 * caller can see -- the admin route's existing no-filter behavior, and a
 * non-admin's full accessible-workspace set); a specific id narrows to just
 * that one. The initial value, absent a stored choice, is the caller's first
 * workspace rather than "All" -- several existing pages (Guardrails,
 * Scan Schedules, Tool Marketplace, ...) require a real workspace_id to
 * fetch anything at all, and defaulting to "All" would land a first-time
 * visitor on an empty/disabled view of those pages instead of the working
 * single-workspace view `useWorkspacePicker` always gave them. "All" is
 * always one click away in the switcher for pages that support it.
 *
 * This is the first React Context in the app (no precedent to follow for
 * global client state -- AuthUser itself is fetched per-page, not shared).
 *
 * Persistence follows the same per-user, try/catch-guarded localStorage
 * convention as lib/dashboard-preferences.ts (a shared workstation is normal
 * here; one operator's active workspace must not become the next operator's
 * default). A stored id that no longer appears in the fetched workspace list
 * (deleted workspace, or a different user's leftover choice on a shared
 * machine) is treated the same as "nothing stored" rather than surfaced as
 * an error.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, type WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import type { UseAsyncDataResult } from "@/hooks/use-async-data";

const STORAGE_KEY_PREFIX = "toleman-active-workspace";
const ALL_WORKSPACES_SENTINEL = "all";

function storageKey(userId: number): string {
  return `${STORAGE_KEY_PREFIX}:${userId}`;
}

function readStored(userId: number | null): number | null | undefined {
  if (typeof window === "undefined" || userId === null) return undefined;
  let raw: string | null;
  try {
    raw = window.localStorage.getItem(storageKey(userId));
  } catch {
    return undefined;
  }
  if (raw === null) return undefined;
  if (raw === ALL_WORKSPACES_SENTINEL) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function writeStored(userId: number | null, workspaceId: number | null): void {
  if (typeof window === "undefined" || userId === null) return;
  try {
    window.localStorage.setItem(
      storageKey(userId),
      workspaceId === null ? ALL_WORKSPACES_SENTINEL : String(workspaceId),
    );
  } catch {
    // Best-effort: a refused write just means the choice will not survive a
    // reload, same trade-off dashboard-preferences.ts makes.
  }
}

export type WorkspaceContextValue = {
  workspaces: WorkspaceSummary[] | null;
  /** null = "All workspaces". */
  activeWorkspaceId: number | null;
  setActiveWorkspaceId: (id: number | null) => void;
  isLoading: boolean;
  error: Error | null;
  reload: () => void;
  /** The underlying request, whole, for a caller that needs the full
   * `<AsyncContent>` ladder (initial skeleton, error-with-retry, stale-
   * data-plus-retry banner, empty) rather than the flattened fields above --
   * same reasoning as the old `useWorkspacePicker`'s `state` field. */
  state: UseAsyncDataResult<WorkspaceSummary[]>;
};

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function WorkspaceProvider({
  userId,
  children,
}: {
  /** The signed-in user's id, for per-user storage keying; null while unauthenticated. */
  userId: number | null;
  children: React.ReactNode;
}) {
  const asyncState = useAsyncData<WorkspaceSummary[]>(() => api.workspaces());
  const { data, error, isInitialLoading, refetch } = asyncState;

  // undefined = "not decided yet" (nothing read from storage, or none
  // applies before the workspace list has loaded); null is itself a real
  // value here ("All workspaces"), so it cannot double as "unset".
  const [chosen, setChosen] = useState<number | null | undefined>(undefined);

  // Re-read storage when the signed-in user changes (e.g. a shared machine
  // logging out and back in as someone else) rather than only on first mount.
  const lastUserIdRef = useRef(userId);
  useEffect(() => {
    if (lastUserIdRef.current !== userId) {
      lastUserIdRef.current = userId;
      setChosen(undefined);
    }
  }, [userId]);

  const activeWorkspaceId = useMemo<number | null>(() => {
    if (chosen !== undefined) return chosen;
    const stored = readStored(userId);
    if (stored !== undefined && (stored === null || (data ?? []).some((w) => w.id === stored))) {
      return stored;
    }
    return data?.[0]?.id ?? null;
  }, [chosen, userId, data]);

  const setActiveWorkspaceId = useCallback(
    (id: number | null) => {
      setChosen(id);
      writeStored(userId, id);
    },
    [userId],
  );

  return (
    <WorkspaceContext.Provider
      value={useMemo(
        () => ({
          workspaces: data,
          activeWorkspaceId,
          setActiveWorkspaceId,
          isLoading: isInitialLoading,
          error,
          reload: refetch,
          state: asyncState,
        }),
        [data, activeWorkspaceId, setActiveWorkspaceId, isInitialLoading, error, refetch, asyncState],
      )}
    >
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspaceContext(): WorkspaceContextValue {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error("useWorkspaceContext must be used within a WorkspaceProvider");
  return ctx;
}
