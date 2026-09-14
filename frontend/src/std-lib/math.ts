/**
 * Standard Library Math & Number Utilities
 */

/**
 * Clamps a number between an inclusive lower and upper bound.
 *
 * @param value The value to clamp
 * @param min Lower boundary
 * @param max Upper boundary
 * @returns The clamped value
 *
 * @example
 * ```ts
 * clamp(105, 0, 100); // 100
 * clamp(-5, 0, 100);  // 0
 * clamp(42, 0, 100);  // 42
 * ```
 */
export function clamp(value: number, min: number, max: number): number {
  if (min > max) {
    throw new RangeError(`min (${min}) cannot be greater than max (${max})`);
  }
  return Math.min(Math.max(value, min), max);
}

/**
 * Formats a decimal ratio (e.g. 0.854) into a formatted percentage string (e.g. "85%").
 *
 * @param ratio Decimal ratio from 0 to 1 (or beyond)
 * @param decimals Number of decimal digits to include (default: 0)
 * @returns Formatted percentage string
 *
 * @example
 * ```ts
 * formatPercent(0.854);    // "85%"
 * formatPercent(0.854, 1); // "85.4%"
 * ```
 */
export function formatPercent(ratio: number, decimals = 0): string {
  return `${(ratio * 100).toFixed(decimals)}%`;
}

/**
 * Rounds a number to a specified decimal precision.
 *
 * @param value The number to round
 * @param decimals The number of decimal places (default: 2)
 * @returns The rounded number
 *
 * @example
 * ```ts
 * roundTo(3.14159, 2); // 3.14
 * roundTo(3.14159, 3); // 3.142
 * ```
 */
export function roundTo(value: number, decimals = 2): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}
