"use client";

// Stand-in for the two real modules that caused #196 and #204: a client
// component that also exports a constant, a function and a type.
export const THEME_COOKIE_KEY = "rikugan-theme";

export function pageSizeFromParams(raw?: string) {
  return Number(raw) || 25;
}

export type Theme = "dark" | "light";

export function ThemeToggle() {
  return <button>toggle</button>;
}
