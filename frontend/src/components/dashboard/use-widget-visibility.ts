"use client";

import { useSyncExternalStore } from "react";
import {
  readWidgetVisibility,
  serverWidgetVisibility,
  subscribeWidgetVisibility,
  type VisibilitySnapshot,
} from "@/lib/dashboard-preferences";

/**
 * Reads this browser's stored widget-visibility preference for one user.
 *
 * `useSyncExternalStore` rather than an effect-plus-setState: the dashboard
 * is server-rendered, localStorage exists only on the client, and this is
 * the one API that lets the server pass (and hydration match) on the
 * role-derived default before swapping in the stored preference. Deriving it
 * in an effect would both flag `react-hooks/set-state-in-effect` and render
 * one frame of the wrong dashboard.
 *
 * `readWidgetVisibility` memoises its parse against the raw stored string, so
 * repeated snapshot reads return the same object and this does not loop.
 */
export function useStoredWidgetVisibility(userId: number | null): VisibilitySnapshot {
  return useSyncExternalStore(
    subscribeWidgetVisibility,
    () => readWidgetVisibility(userId),
    serverWidgetVisibility,
  );
}
