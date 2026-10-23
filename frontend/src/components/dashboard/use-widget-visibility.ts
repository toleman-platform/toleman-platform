"use client";

import { useSyncExternalStore } from "react";
import {
  readWidgetVisibility,
  serverWidgetVisibility,
  subscribeWidgetVisibility,
  type VisibilitySnapshot,
} from "@/lib/dashboard-preferences";

/**
 * Use useSyncExternalStore to hydrate with role-derived defaults before applying
 * per-user localStorage preferences. readWidgetVisibility memoizes by raw storage text
 * so repeated snapshots retain object identity and cannot loop.
 */
export function useStoredWidgetVisibility(userId: number | null): VisibilitySnapshot {
  return useSyncExternalStore(
    subscribeWidgetVisibility,
    () => readWidgetVisibility(userId),
    serverWidgetVisibility,
  );
}
