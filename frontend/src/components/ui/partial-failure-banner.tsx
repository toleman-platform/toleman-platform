import * as React from "react";
import { AlertBanner } from "@/components/ui/alert-banner";

/**
 * One secondary data source a page loaded, and what the page loses without it.
 *
 * `consequence` is the whole point: "Scan history is unavailable" tells the
 * reader nothing they can act on, whereas "freshness and tool history are not
 * shown, and rows read `—` rather than `never scanned`" tells them exactly
 * which of the numbers in front of them they may not trust. `DESIGN_SYSTEM.md`
 * §20 asks for contextual errors over generic ones, and this is the contextual
 * half.
 */
export type PartialFailureSource = {
  /** Human name of the source, e.g. "Scan history". */
  label: string;
  /** True when this source failed to load. */
  failed: boolean;
  /** What the page cannot show or cannot be trusted on as a result. */
  consequence: string;
};

/**
 * Show partial request failures while preserving successfully loaded content. Pair with
 * settledOr to retain and display failure flags; empty fallbacks must not masquerade as
 * measured results. Renders nothing when all sources load.
 */
export function PartialFailureBanner({
  sources,
  action,
  className,
}: {
  sources: PartialFailureSource[];
  /** Usually a `<ReloadButton />`. */
  action?: React.ReactNode;
  className?: string;
}) {
  const failed = sources.filter((s) => s.failed);
  if (failed.length === 0) return null;

  const loaded = sources.length - failed.length;

  return (
    <AlertBanner
      tone="warning"
      // Counted rather than just named, per §20's own example copy. "1 of 3
      // data sources failed to load" sets the reader's expectation for how
      // much of the page below is still trustworthy before they read a single
      // number on it.
      title={`${loaded} of ${sources.length} data source${sources.length === 1 ? "" : "s"} loaded`}
      action={action}
      className={className}
    >
      <ul className="flex flex-col gap-0.5">
        {failed.map((s) => (
          <li key={s.label}>
            <span className="font-medium text-foreground">{s.label}</span> is unavailable. {s.consequence}
          </li>
        ))}
      </ul>
    </AlertBanner>
  );
}
