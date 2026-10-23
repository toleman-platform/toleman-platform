"use client";

import { useLayoutEffect, useState, useEffect } from "react";
import { Moon, Sun, Laptop } from "lucide-react";
import { cn } from "@/lib/utils";
import { THEME_COOKIE_KEY, THEME_STORAGE_KEY, type Theme } from "@/tokens";

// Re-exported for existing importers. Server Components must import these
// from "@/lib/theme" directly; see that module's comment for why importing
// them from this ("use client") file silently breaks the server-side read.
export { THEME_COOKIE_KEY, THEME_STORAGE_KEY };
export type { Theme };

const STORAGE_KEY = THEME_STORAGE_KEY;

/**
 * Dark is default; light uses data-theme token overrides. The root layout reads the
 * theme cookie for correct first paint. Persist cookie and localStorage together;
 * ThemeInit reconciles page colors when the cookie is missing/stale.
 */
function getSystemTheme(): "dark" | "light" {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyTheme(theme: Theme) {
  const resolved = theme === "system" ? getSystemTheme() : theme;
  if (resolved === "light") {
    document.documentElement.dataset.theme = "light";
  } else {
    delete document.documentElement.dataset.theme;
  }
}

function persistTheme(theme: Theme) {
  window.localStorage.setItem(STORAGE_KEY, theme);
  // 1 year, lax, no Secure requirement so this also works over plain http in
  // local/dev docker-compose; this cookie carries no sensitive data, it's
  // purely a rendering preference read by the root layout.
  document.cookie = `${THEME_COOKIE_KEY}=${theme}; path=/; max-age=31536000; samesite=lax`;
}

export function toggleTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  const next: Theme = current === "dark" ? "light" : "dark";
  applyTheme(next);
  persistTheme(next);
  return next;
}

function readStoredTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored === "light" || stored === "system" ? stored : "dark";
}

/** See the FOUC-handling note above; this is a client-side safety net,
 * not the primary defense (that's the server-rendered `data-theme`
 * attribute in src/app/layout.tsx). */
export function ThemeInit() {
  useLayoutEffect(() => {
    applyTheme(readStoredTheme());
  }, []);

  // Live listener for OS theme preference changes when mode is "system"
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const listener = () => {
      if (readStoredTheme() === "system") {
        applyTheme("system");
      }
    };
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, []);

  return null;
}

/**
 * Interactive button cycling the color theme through Dark -> Light -> System.
 *
 * Persists the selection to both `localStorage` and a `toleman-theme` cookie.
 * Accepts `initialTheme` (read server-side from the cookie) to ensure the client
 * button matches server-rendered HTML on first paint without hydration mismatch.
 */
export function ThemeToggle({
  collapsed,
  compact,
  initialTheme = "dark",
}: {
  collapsed?: boolean;
  compact?: boolean;
  initialTheme?: Theme;
}) {
  // Initialize from the server cookie to match SSR markup; reading localStorage in the
  // first client render can cause hydration mismatch. persistTheme writes both stores.
  // ThemeInit reconciles page colors on mount; this button follows initialTheme until
  // clicked.
  const [theme, setTheme] = useState<Theme>(initialTheme);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
    setTheme(next);
    applyTheme(next);
    persistTheme(next);
  }

  const tooltipLabel =
    theme === "dark"
      ? "Theme: Dark (click for Light)"
      : theme === "light"
      ? "Theme: Light (click for System)"
      : "Theme: System (click for Dark)";

  return (
    <button
      onClick={toggle}
      title={tooltipLabel}
      aria-label={tooltipLabel}
      className={cn(
        "flex items-center justify-center gap-2 rounded-md text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground",
        // `compact` is the sidebar footer's icon-row mode (see sidebar.tsx):
        // three full-width stacked rows cost ~90px of vertical space for
        // controls used once a session. `collapsed` is the separate icon-rail
        // case, where the rail is too narrow to fit three across.
        compact ? "h-8 w-8 shrink-0" : "w-full px-3 py-1.5",
        collapsed && !compact && "px-2"
      )}
    >
      {theme === "dark" ? (
        <Moon className="h-4 w-4" />
      ) : theme === "light" ? (
        <Sun className="h-4 w-4" />
      ) : (
        <Laptop className="h-4 w-4" />
      )}
      {!collapsed && !compact && (
        <span className="capitalize">{theme}</span>
      )}
    </button>
  );
}
