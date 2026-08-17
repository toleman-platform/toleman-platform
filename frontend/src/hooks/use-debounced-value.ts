"use client";

import { useEffect, useState } from "react";

/**
 * Trailing-edge debounce for a value (issue #210).
 *
 * Pairs with `useAsyncData`: debounce the input, then declare the debounced
 * value as a dependency, and the request fires once the user stops typing
 * instead of on every keystroke. Keeping the two apart matters -- a fetch
 * hook that also owned debouncing would have to re-implement the request-id
 * and abort handling for the timer case.
 *
 * The value updates on the trailing edge only. A leading-edge variant would
 * fire a request for the first character of every search, which is the
 * request this is meant to avoid.
 */
export function useDebouncedValue<T>(value: T, delayMs = 200): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const handle = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(handle);
  }, [value, delayMs]);

  return debounced;
}
