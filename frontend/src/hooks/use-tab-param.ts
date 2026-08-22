"use client";

import { useCallback } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

// Issue #235 (UI-02): Control Plane and Guardrails each kept their active
// tab in a plain useState, so leaving the page and coming back always
// landed on the first tab, and no page deeper than the top level could be
// linked to a colleague or from our own docs -- "go to Control Plane >
// Tooling > Tool Marketplace" had no URL to point at.
//
// target-tabs.tsx already solved exactly this for target sub-pages (#197)
// with a `?tab=` query param rendered as real <Link>s, keeping that page a
// Server Component. Control Plane and Guardrails can't take that shape
// directly -- both are "use client" pages whose tab content components do
// their own client-side data fetching -- so this hook applies the same
// underlying fix (the URL is the source of truth, not component state)
// without requiring the bigger Server Component refactor.
//
// router.push, not replace: matches the convention already established by
// findings-filter-bar.tsx's updateParam, so switching tabs behaves the same
// way as every other URL-driven control in this app, including working
// with the back button.
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
