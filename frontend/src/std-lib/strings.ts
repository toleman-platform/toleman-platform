import type { Nullable } from "./types";

/**
 * Standard Library String & URL Utilities
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

/**
 * Generates a direct GitHub blob link pointing to a file and optional line number.
 * Properly encodes repo path, branch name, and nested file path segments.
 *
 * @param repoUrl Full repository URL (e.g. "https://github.com/org/repo")
 * @param branch Branch name (e.g. "feature/cool-branch")
 * @param filePath Path to file within repo (e.g. "src/lib/app.ts")
 * @param lineStart Optional 1-based start line number
 * @returns Formatted and encoded GitHub blob URL
 */
export function githubBlobUrl(
  repoUrl: string,
  branch: string,
  filePath: string,
  lineStart?: Nullable<number>,
): string {
  const repoPath = new URL(repoUrl).pathname.replace(/\.git$/, "").replace(/^\//, "");
  const encodedFilePath = filePath.split("/").map(encodeURIComponent).join("/");
  const url = `https://github.com/${repoPath}/blob/${encodeURIComponent(branch)}/${encodedFilePath}`;
  return lineStart ? `${url}#L${lineStart}` : url;
}
