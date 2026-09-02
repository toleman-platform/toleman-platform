/**
 * Standard Library String Utilities
 */

/**
 * Truncates a string to the specified maximum length and appends an ellipsis if truncated.
 *
 * @param str The string to truncate
 * @param maxLength Maximum allowed length
 * @param ellipsis The suffix to append (default: "…")
 * @returns Truncated string
 *
 * @example
 * ```ts
 * truncate("Hello, world!", 5); // "Hello…"
 * truncate("Short", 10);        // "Short"
 * ```
 */
export function truncate(str: string, maxLength: number, ellipsis = "…"): string {
  if (str.length <= maxLength) {
    return str;
  }
  return `${str.slice(0, maxLength)}${ellipsis}`;
}

/**
 * Capitalizes the first character of a string.
 *
 * @param str The string to capitalize
 * @returns String with first letter uppercase
 *
 * @example
 * ```ts
 * capitalize("warning"); // "Warning"
 * ```
 */
export function capitalize(str: string): string {
  if (!str) return "";
  return `${str.charAt(0).toUpperCase()}${str.slice(1)}`;
}
