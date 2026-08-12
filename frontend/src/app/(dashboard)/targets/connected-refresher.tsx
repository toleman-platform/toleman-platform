"use client";

import { useEffect } from "react";
import { useRouter, useSearchParams, usePathname } from "next/navigation";

/**
 * The GitHub App install flow ends with an external redirect back to
 * /targets?connected=1. Next's client router cache can still be holding an
 * RSC payload from before the install (e.g. this tab already had /targets
 * open), so the freshly-synced targets don't show up without a forced
 * refresh. This does that once, then strips the query param.
 */
export function ConnectedRefresher() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (searchParams.get("connected") === "1") {
      router.refresh();
      router.replace(pathname);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}
