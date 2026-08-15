"use client";

import { useLayoutEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { cn } from "@/lib/utils";
import { THEME_COOKIE_KEY, THEME_STORAGE_KEY, type Theme } from "@/lib/theme";

// Re-exported for existing importers. Server Components must import these
// from "@/lib/theme" directly -- see that module's comment for why importing
// them from this ("use client") file silently breaks the server-side read.
export { THEME_COOKIE_KEY, THEME_STORAGE_KEY };
export type { Theme };

const STORAGE_KEY = THEME_STORAGE_KEY;

/**
 * Light/dark theme toggle (#115). Dark is the app's original, unchanged
 * default; light opts in via `data-theme="light"` on <html>, read by the
 * `:root[data-theme="light"]` token overrides in globals.css.
 *
 * FOUC handling deliberately does NOT follow density-toggle.tsx's
 * useLayoutEffect-only approach: density is a subtle spacing change where a
 * one-frame flash is an acceptable trade-off (documented there), but a full
 * dark<->light color flip is much more jarring, and the raw server HTML
 * paints before React ever hydrates -- a client-only fix can't prevent that
 * first paint from being wrong. Instead, the root layout (a Server
 * Component, see src/app/layout.tsx) reads a `rikugan-theme` cookie via
 * `next/headers` and renders `<html data-theme="...">` directly in the
 * initial HTML, so there's nothing to flash. ThemeToggle keeps both
 * localStorage (read here, client-side) and that cookie (read server-side)
 * in sync on every change; ThemeInit below is a lightweight client-side
 * safety net for the (rare) case the cookie is missing/stale but
 * localStorage still has the real preference, e.g. a cookie clear that
 * didn't also clear localStorage.
 */
function applyTheme(theme: Theme) {
  if (theme === "light") {
    document.documentElement.dataset.theme = "light";
  } else {
    delete document.documentElement.dataset.theme;
  }
}

function persistTheme(theme: Theme) {
  window.localStorage.setItem(STORAGE_KEY, theme);
  // 1 year, lax, no Secure requirement so this also works over plain http in
  // local/dev docker-compose -- this cookie carries no sensitive data, it's
  // purely a rendering preference read by the root layout.
  document.cookie = `${THEME_COOKIE_KEY}=${theme}; path=/; max-age=31536000; samesite=lax`;
}

function readStoredTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored === "light" ? "light" : "dark";
}

/** See the FOUC-handling note above -- this is a client-side safety net,
 * not the primary defense (that's the server-rendered `data-theme`
 * attribute in src/app/layout.tsx). */
export function ThemeInit() {
  useLayoutEffect(() => {
    applyTheme(readStoredTheme());
  }, []);
  return null;
}

export function ThemeToggle({ collapsed, initialTheme = "dark" }: { collapsed?: boolean; initialTheme?: Theme }) {
  // `initialTheme` comes from the same server-side cookie read that drives
  // the `data-theme` attribute in src/app/layout.tsx (threaded down through
  // DashboardLayout -> Sidebar -> here) so the very first client render
  // matches the server-rendered HTML exactly. Reading localStorage directly
  // in a useState lazy initializer -- the pattern DensityToggle uses --
  // looks equivalent but isn't: it runs during the client's first render
  // too, and localStorage is client-only, so it can disagree with what the
  // server actually sent and trigger a real hydration-mismatch error (this
  // was caught live: the button's `title` differed between server and
  // client on first paint).
  //
  // There's deliberately no effect here reconciling `theme` against
  // localStorage on mount: the cookie (server-known, drives `initialTheme`)
  // and localStorage are always written together by `persistTheme` below,
  // so they only disagree in a rare manual-tampering edge case -- not worth
  // a `setState`-in-effect (flagged by react-hooks/set-state-in-effect,
  // and a real cascading-render smell) to guard against. `ThemeInit`
  // already corrects the actual page colors (the part that matters) from
  // localStorage on every mount; this button's own label just follows
  // `initialTheme` until the user clicks it.
  const [theme, setTheme] = useState<Theme>(initialTheme);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
    persistTheme(next);
  }

  return (
    <button
      onClick={toggle}
      title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      className={cn(
        "flex w-full items-center justify-center gap-2 rounded-md px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground",
        collapsed && "px-2"
      )}
    >
      {theme === "dark" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
      {!collapsed && <span>{theme === "dark" ? "Dark" : "Light"}</span>}
    </button>
  );
}
