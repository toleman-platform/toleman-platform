// Generic polling helper for the async job pattern introduced in #59:
// POST /api/scans/run, /api/discovery/{id}, /api/sbom/{id} now dispatch a
// Celery task and return immediately with status: "running" instead of
// blocking until the scan/discovery/SBOM generation finishes. Every caller
// polls the matching GET endpoint on an interval until the job leaves
// "running", so this is factored out once instead of three near-identical
// setInterval blocks.

export type PollableStatus = "running" | "completed" | "failed";

/**
 * Polls `fetchStatus` every `intervalMs` until it returns a result whose
 * `status` is no longer "running", then resolves with that result. Stops
 * (and rejects) after `timeoutMs` so a stuck job can't spin the UI forever.
 * Returns a cancel function so a caller can stop polling early (e.g. the
 * component unmounts or the user switches targets).
 */
export function pollUntilSettled<T extends { status: PollableStatus }>(
  fetchStatus: () => Promise<T>,
  onUpdate: (result: T) => void,
  options: { intervalMs?: number; timeoutMs?: number; onError?: (err: unknown) => void } = {},
): () => void {
  const intervalMs = options.intervalMs ?? 2000;
  const timeoutMs = options.timeoutMs ?? 5 * 60 * 1000;
  const startedAt = Date.now();
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  async function tick() {
    if (cancelled) return;
    try {
      const result = await fetchStatus();
      if (cancelled) return;
      onUpdate(result);
      if (result.status === "running") {
        if (Date.now() - startedAt > timeoutMs) {
          options.onError?.(new Error("timed out waiting for job to complete"));
          return;
        }
        timer = setTimeout(tick, intervalMs);
      }
    } catch (err) {
      if (!cancelled) options.onError?.(err);
    }
  }

  timer = setTimeout(tick, intervalMs);

  return () => {
    cancelled = true;
    if (timer) clearTimeout(timer);
  };
}
