// No "use client" -- the shape both fixes moved to (@/lib/theme,
// @/lib/pagination). A Server Component may import freely from here.
export const THEME_COOKIE_KEY = "toleman-theme";

export function pageSizeFromParams(raw?: string) {
  return Number(raw) || 25;
}
