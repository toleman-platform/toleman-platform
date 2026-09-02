/**
 * URL sanitization helper for preventing DOM-based XSS vulnerabilities (#275).
 *
 * Ensures dynamic values interpolated into `<a href={...}>` attributes only use safe
 * http: or https: schemes, rejecting dangerous javascript:, data:, and vbscript: URLs.
 */

/**
 * Validates and sanitizes a URL for safe usage in anchor href attributes.
 *
 * Returns the URL string if safe (http or https), or undefined if malformed or dangerous.
 * Returning undefined allows standard `{url && <a href={safeHref(url)}>}` JSX patterns
 * to degrade gracefully to no link rendered instead of rendering dead or dangerous links.
 *
 * @param url Target URL to sanitize
 * @returns Safe URL string or undefined
 */
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url, typeof window === "undefined" ? "http://localhost" : window.location.href);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}
