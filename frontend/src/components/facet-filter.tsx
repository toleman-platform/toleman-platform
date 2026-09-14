"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { cn } from "@/lib/utils";

// `count: null` means "not counted", not "counted zero" -- the facets call
// failed and the bar is running on the plain option lists. The pill then
// shows no number at all rather than a 0, which would be a specific and
// false claim about the backlog.
export type FacetOption = { value: string; label: string; count: number | null };

// How many options a facet shows before collapsing the rest behind "+N
// more". Six covers severity, state and fixability outright; tools, owners
// and environments are the ones that can run long on a real instance (35
// repos across a dozen scanners), and an always-expanded wall of pills
// would bury the filters people actually reach for.
//
// Options keep the stable order the API returns them in (the severity
// ladder, then alphabetical) rather than being re-sorted by count: pills
// that reshuffle every time you tick a box are unusable, and the count is
// already on each one.
const DEFAULT_VISIBLE = 6;

// (#270) One filter dimension, rendered as a row of toggle pills with the
// count on each one.
//
// This replaces MultiSelectFilter for the dimensions the backend can count
// (severity/state/tool/fixability/environment/owner). The difference is the
// whole point of the issue: a dropdown hides its options until you open it,
// so the only way to learn there are 12 Criticals was to filter to Critical
// and read the result count. Pills put the shape of the backlog on the page
// -- you read it instead of operating it.
//
// Deliberately uniform styling across every dimension rather than severity
// colours here: six dimensions of coloured pills would drown the numbers,
// and the numbers are the reason this component exists. Severity keeps its
// semantic colour where it identifies a *finding* (finding rows, badges),
// not where it labels a control.
//
// Same "URL is the source of truth" convention as every other filter on
// this page (multi-select-filter.tsx, group-filter.tsx): each toggle pushes
// a repeated query param, so a filtered view survives reload, back/forward
// and being pasted to a colleague.
export function FacetFilter({
  label,
  paramKey,
  options,
  visibleCount = DEFAULT_VISIBLE,
}: {
  label: string;
  paramKey: string;
  options: FacetOption[];
  visibleCount?: number;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [expanded, setExpanded] = useState(false);
  const selected = searchParams.getAll(paramKey);

  // Anything currently selected is always an option, even if the API never
  // offered it -- a stale URL, or the facets call failing and the fallback
  // option list not containing it. A control that hides itself while its
  // own filter is still narrowing the list strands that filter: the URL
  // still carries ?tool=semgrep, the list is still cut down by it, and the
  // only control that could switch it off is gone. ("Clear filters" would
  // still work, but only once you guessed that an invisible filter is why
  // the list looks wrong.)
  const known = new Set(options.map((o) => o.value));
  const allOptions: FacetOption[] = [
    ...options,
    ...selected.filter((v) => !known.has(v)).map((v) => ({ value: v, label: v, count: null })),
  ];

  // A genuinely empty dimension is different: nothing in this workspace has
  // ever carried it (no target has an owner recorded, no scan has run), and
  // an empty control is just noise. The closed enums (severity, state,
  // fixability) always have options, so they are never hidden by this.
  if (allOptions.length === 0) return null;

  function toggle(value: string) {
    const params = new URLSearchParams(searchParams.toString());
    params.delete(paramKey);
    const next = selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value];
    next.forEach((v) => params.append(paramKey, v));
    // Back to page 1: the current page number means nothing against a
    // different result set.
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  }

  function clear() {
    const params = new URLSearchParams(searchParams.toString());
    params.delete(paramKey);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  }

  // A selected option stays visible even when it sits past the cut: the one
  // filter you are actually using must never be the one hidden behind
  // "+N more".
  const visible = expanded
    ? allOptions
    : allOptions.filter((option, index) => index < visibleCount || selected.includes(option.value));
  const hiddenCount = allOptions.length - visible.length;

  return (
    <div role="group" aria-label={label} className="flex min-w-0 flex-col gap-1.5">
      <div className="flex items-baseline gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
        {selected.length > 0 && (
          <button
            type="button"
            onClick={clear}
            className="text-[11px] text-muted-foreground underline hover:text-foreground"
          >
            Clear
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-1">
        {visible.map((option) => {
          const isSelected = selected.includes(option.value);
          return (
            <button
              key={option.value}
              type="button"
              aria-pressed={isSelected}
              // Spelled out rather than left to the label and count spans.
              // They are adjacent inline elements, so the computed
              // accessible name concatenates them with no separator: the
              // "tool-0" pill showing 0 announced as "tool-00", and
              // "Critical" showing 12 as "Critical12". Every consumer that
              // addresses a control by its name -- a screen reader, voice
              // control, a test -- then gets a value that is not the
              // option's and is ambiguous between options.
              aria-label={
                option.count === null ? option.label : `${option.label}, ${option.count} findings`
              }
              onClick={() => toggle(option.value)}
              className={cn(
                "flex h-7 max-w-[220px] items-center gap-1.5 rounded-md border px-2 text-xs transition-colors focus:outline-none focus:ring-1 focus:ring-ring",
                isSelected
                  ? "border-primary bg-primary/10 text-foreground"
                  : "border-input bg-secondary text-foreground hover:border-ring",
                // A zero-count option is shown, not hidden: "nothing matches
                // this right now" and "this dimension doesn't exist" are
                // different facts, and only one of them is worth acting on.
                // Still clickable, matching the category tabs' own call on
                // an empty tab (findings-category-tabs.tsx) -- an empty
                // result is a legitimate, linkable destination.
                !isSelected && option.count === 0 && "text-muted-foreground opacity-60",
              )}
            >
              <span className="truncate">{option.label}</span>
              {option.count !== null && (
                <span className="shrink-0 font-mono tabular-nums text-muted-foreground">{option.count}</span>
              )}
            </button>
          );
        })}
        {hiddenCount > 0 && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="h-7 rounded-md px-2 text-xs text-muted-foreground underline hover:text-foreground"
          >
            +{hiddenCount} more
          </button>
        )}
        {expanded && allOptions.length > visibleCount && (
          <button
            type="button"
            onClick={() => setExpanded(false)}
            className="h-7 rounded-md px-2 text-xs text-muted-foreground underline hover:text-foreground"
          >
            Show less
          </button>
        )}
      </div>
    </div>
  );
}
