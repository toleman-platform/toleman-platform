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
 * The shared "some of this page loaded, some did not" banner.
 *
 * `DESIGN_SYSTEM.md` §20 specifies a partial-failure state — *"3 of 4 scanner
 * sources loaded. Snyk data is temporarily unavailable."*, and explicitly
 * *"Do NOT discard successfully loaded information because one secondary
 * request failed"* — but until now it had no implementation anywhere in the
 * operator surfaces. What the surfaces did instead was catch the failure,
 * substitute an empty collection, and render the result as fact: a failed
 * `/api/scans/summary` painted all 33 targets "never scanned", a failed
 * `/api/targets/summary` produced a green `0` under the words "scanned,
 * nothing open".
 *
 * This component is the other half of `settledOr` (`std-lib/async.ts`): that
 * one keeps the failure bit alive past the call site, this one puts it on the
 * screen. Pair them, and the honest path stays the short path.
 *
 * Renders nothing when every source loaded, so a caller can mount it
 * unconditionally and not fork its JSX on the happy path.
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
