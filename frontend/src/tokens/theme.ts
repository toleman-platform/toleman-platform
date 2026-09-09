/**
 * Theme constants shared by Server Components and client-side theme controls.
 *
 * Deliberately plain module without `"use client"` so cookies and default theme
 * can be safely referenced server-side without generating client reference stubs.
 */
export type Theme = "dark" | "light" | "system";

export const THEME_STORAGE_KEY = "toleman-theme";
export const THEME_COOKIE_KEY = "toleman-theme";
