"use client";

import { useCallback } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

// Keep client-page tabs in the URL for reloads and deep links. Use router.push to match
// other filters and preserve back-button navigation.
export function useTabParam<T extends string>(
  validTabs: readonly T[],
  defaultTab: T,
  paramName = "tab",
): [T, (next: T) => void] {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const raw = searchParams.get(paramName);
  const tab = raw && (validTabs as readonly string[]).includes(raw) ? (raw as T) : defaultTab;

  const setTab = useCallback(
    (next: T) => {
      const params = new URLSearchParams(searchParams.toString());
      // Omit the param entirely for the default tab, so the plain,
      // shareable URL (no query string) is the common case rather than
      // always carrying `?tab=<default>`.
      if (next === defaultTab) params.delete(paramName);
      else params.set(paramName, next);
      const query = params.toString();
      router.push(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [router, pathname, searchParams, defaultTab, paramName],
  );

  return [tab, setTab];
}
