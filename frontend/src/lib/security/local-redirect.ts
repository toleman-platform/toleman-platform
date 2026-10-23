/** Return only a local path; login destinations come from an untrusted URL. */
export function localRedirectPath(value: string | null | undefined): string {
  if (!value?.startsWith("/") || /[\\\u0000-\u0020\u007f]/.test(value)) return "/";
  const origin = "https://toleman.invalid";
  try {
    const url = new URL(value, origin);
    // Check again after URL normalization: /a/..//host becomes //host.
    if (url.origin !== origin || url.pathname.startsWith("//")) return "/";
    return url.pathname + url.search + url.hash;
  } catch {
    return "/";
  }
}
