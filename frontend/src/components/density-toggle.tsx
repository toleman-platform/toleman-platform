"use client";

import { useLayoutEffect, useState } from "react";
import { AlignJustify, Rows3 } from "lucide-react";
import { cn } from "@/lib/utils";

export type Density = "comfortable" | "compact";
export const DENSITY_STORAGE_KEY = "osp-density";
const STORAGE_KEY = DENSITY_STORAGE_KEY;

function applyDensity(density: Density) {
  document.documentElement.dataset.density = density;
}

/**
 * Power-user "compact" vs exec-friendly "comfortable" density mode (#77).
 * Persisted in localStorage, applied as `data-density` on <html> (read by
 * the `--density-*` custom properties in globals.css and by components that
 * branch on it directly, e.g. findings-list row padding).
 */
function readStoredDensity(): Density {
  if (typeof window === "undefined") return "comfortable";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored === "compact" ? "compact" : "comfortable";
}

/**
 * Applies the persisted density to `<html data-density>` as early as
 * possible on mount -- rendered once near the top of the body in the root
 * layout. Uses `useLayoutEffect` (fires synchronously before the browser
 * paints) rather than a raw `<script dangerouslySetInnerHTML>`/next/script
 * `beforeInteractive` injection: both of those produced a real
 * hydration-mismatch / "Invalid or unexpected token" error in this app's
 * Turbopack dev setup, and mutating a DOM attribute outside React's own
 * state (no setState call here) is exactly what `useLayoutEffect` is for.
 * There's a theoretical one-frame flash on first paint for compact-density
 * users vs. a blocking inline script, which is an acceptable trade-off for
 * a progressive-enhancement density mode.
 */
export function DensityInit() {
  useLayoutEffect(() => {
    applyDensity(readStoredDensity());
  }, []);
  return null;
}

export function DensityToggle({ collapsed }: { collapsed?: boolean }) {
  // Lazy initializer (not an effect + setState) so this reads localStorage
  // exactly once on mount without the "setState synchronously in an effect"
  // cascading-render smell -- <DensityInit /> (rendered once, near the top
  // of <body>) already applied the data-density attribute; this just keeps
  // the button's own label/icon state in sync with it.
  const [density, setDensity] = useState<Density>(readStoredDensity);

  function toggle() {
    const next: Density = density === "comfortable" ? "compact" : "comfortable";
    setDensity(next);
    applyDensity(next);
    window.localStorage.setItem(STORAGE_KEY, next);
  }

  return (
    <button
      onClick={toggle}
      title={density === "comfortable" ? "Switch to compact density" : "Switch to comfortable density"}
      className={cn(
        "flex w-full items-center justify-center gap-2 rounded-md px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground",
        collapsed && "px-2"
      )}
    >
      {density === "comfortable" ? <Rows3 className="h-4 w-4" /> : <AlignJustify className="h-4 w-4" />}
      {!collapsed && <span>{density === "comfortable" ? "Comfortable" : "Compact"}</span>}
    </button>
  );
}

