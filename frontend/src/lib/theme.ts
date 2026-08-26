/**
 * Theme constants shared by Server Components and the client-side
 * ThemeToggle (#115).
 *
 * These deliberately live in a plain (non-"use client") module. They used to
 * be exported from src/components/theme-toggle.tsx, which carries the
 * "use client" directive, and a Server Component importing a value from a
 * client module doesn't get the value, it gets a client *reference* stub.
 * `cookies().get(THEME_COOKIE_KEY)` was therefore looking up a cookie whose
 * name was that stub rather than the string "toleman-theme", so the
 * server-side read silently returned undefined on every request. That
 * defeated the whole point of the cookie (server-rendered `data-theme`, no
 * flash of the wrong theme) and left the toggle's own label/tooltip stuck
 * reporting "dark" after any full page load in light mode; which in turn
 * made the first click on the toggle a no-op, since it computed its "next"
 * theme from that wrong initial state.
 */
export type Theme = "dark" | "light";

export const THEME_STORAGE_KEY = "toleman-theme";
export const THEME_COOKIE_KEY = "toleman-theme";
