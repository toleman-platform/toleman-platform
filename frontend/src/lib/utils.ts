import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// Re-export specialized utilities for backward compatibility
export { safeHref } from "./security/safe-href";
export { timeAgo } from "./format/date";

/**
 * Merges Tailwind CSS classes with clsx conditionals and tailwind-merge conflict resolution.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Standard root baseline font size in pixels (1rem = 16px) */
export const ROOT_FONT_BASE = 16;

/**
 * Converts pixel values to rem units based on the standard 16px root baseline.
 *
 * @example
 * pixelToRem(16) => "1rem"
 * pixelToRem(14) => "0.875rem"
 * pixelToRem(24, { unit: false }) => "1.5"
 */
export function pixelToRem(
  px: number,
  options?: { base?: number; precision?: number; unit?: boolean },
): string {
  const base = options?.base ?? ROOT_FONT_BASE;
  const precision = options?.precision ?? 4;
  const unit = options?.unit ?? true;
  const remValue = Number((px / base).toFixed(precision));
  return unit ? `${remValue}rem` : String(remValue);
}

/** Alias for pixelToRem */
export const pxToRem = pixelToRem;
