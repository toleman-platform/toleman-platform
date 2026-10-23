"use client";

/**
 * Shared active-workspace state: one workspace fetch and selection for all consumers.
 * Null means all accessible workspaces; absent/invalid saved choices default to the
 * first workspace. Persist per-user selection with guarded localStorage. Mirror the
 * resolved choice to a cookie for Server Components on mount and every change; the
 * non-user-scoped cookie can be one render stale after an account switch and then
 * self-corrects.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, type WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import type { UseAsyncDataResult } from "@/hooks/use-async-data";
import { WORKSPACE_COOKIE_KEY } from "@/lib/workspace-cookie";

export { WORKSPACE_COOKIE_KEY };

const STORAGE_KEY_PREFIX = "toleman-active-workspace";
const ALL_WORKSPACES_SENTINEL = "all";

function writeWorkspaceCookie(workspaceId: number | null): void {
  if (typeof document === "undefined") return;
  const value = workspaceId === null ? ALL_WORKSPACES_SENTINEL : String(workspaceId);
  // 1 year, lax, no Secure requirement -- same as the theme cookie, works
  // over plain http in local/dev docker-compose, and carries no sensitive
  // data.
  document.cookie = `${WORKSPACE_COOKIE_KEY}=${value}; path=/; max-age=31536000; samesite=lax`;
}

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
    // `chosen` wins only while it's still a real choice: "All workspaces"
    // (null) always is, and a specific id is until the list has loaded and
    // no longer contains it (access revoked, or the workspace was deleted)
    // -- an explicit pick from earlier in the session must not outlive the
    // membership it depended on once a fresher list says otherwise.
    if (chosen !== undefined && (chosen === null || data === null || data.some((w) => w.id === chosen))) {
      return chosen;
    }
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
      writeWorkspaceCookie(id);
      // Dashboard/Findings/Targets/Scans fetch their data server-side in a
      // Server Component; writing the cookie above is invisible to a page
      // the reader is already sitting on until something asks Next.js to
      // re-render it, which is why the switcher itself follows this call
      // with a `router.refresh()` -- not done here, so this context has no
      // App Router dependency for callers that don't need it (most of this
      // module's test coverage renders without one).
    },
    [userId],
  );

  // Keeps the cookie in sync with this resolved value even when it changed
  // for a reason other than an explicit pick above (the per-user default on
  // first load, or a different user's storage taking over on a shared
  // machine) -- see the file-level comment for why this mirrors ThemeInit.
  // Gated on `data !== null`: before the workspace list has loaded,
  // `activeWorkspaceId` reads as null ("All workspaces") for lack of
  // anything better, not because that's the resolved answer -- writing that
  // placeholder here would clobber a real, already-correct cookie value for
  // the brief window before the fetch above resolves.
  useEffect(() => {
    if (data === null) return;
    writeWorkspaceCookie(activeWorkspaceId);
  }, [activeWorkspaceId, data]);

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
