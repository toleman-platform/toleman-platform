"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

const INTERVAL_MS = 5000;
const TIMEOUT_MS = 5 * 60 * 1000;

/**
 * (#330) The dependency graph import runs as a background task, so a target
 * page opened right after creation renders with dependency_sync_status
 * "pending" and then never moves: the Server Component fetched the target and
 * the SBOM once, and nothing tells it the task has finished. This refreshes
 * the route on an interval so the import result appears without a reload.
 *
 * Rendered only while the status is pending, so it unmounts and stops on the
 * first refresh that returns a settled status. The timeout is the backstop
 * for a task that never settles at all (a lost worker leaves the row pending
 * forever), so the tab does not poll for the rest of the day.
 */
export function DependencySyncRefresher() {
  const router = useRouter();

  useEffect(() => {
    const startedAt = Date.now();
    const timer = setInterval(() => {
      if (Date.now() - startedAt > TIMEOUT_MS) {
        clearInterval(timer);
        return;
      }
      router.refresh();
    }, INTERVAL_MS);

    return () => clearInterval(timer);
  }, [router]);

  return null;
}
