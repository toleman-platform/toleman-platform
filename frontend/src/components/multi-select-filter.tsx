"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

const TRIGGER_CLASS =
  "flex h-8 items-center gap-1 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

export type MultiSelectOption = { value: string; label: string };

/**
 * The dropdown itself: checkboxes, open/close, summary label. Presentational
 * and fully controlled, so it works both for the Findings page's
 * URL-is-the-source-of-truth filters (via MultiSelectFilter below) and for
 * the Reports page's report builder (#302), whose filters are local state on
 * a form and never touch the URL.
 *
 * Split out rather than giving MultiSelectFilter an optional "controlled"
 * mode: that would mean calling useSearchParams() even where there is no URL
 * state to read, which in the App Router drags a Suspense requirement into
 * every page that renders one.
 */
export function MultiSelectDropdown({
  label,
  options,
  selected,
  onChange,
  ariaLabel,
}: {
  label: string;
  options: MultiSelectOption[];
  selected: string[];
  onChange: (next: string[]) => void;
  /** Defaults to `Filter by {label}`. */
  ariaLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  function toggle(value: string) {
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value]);
  }

  const summary =
    selected.length === 0
      ? label
      : selected.length === 1
        ? (options.find((o) => o.value === selected[0])?.label ?? selected[0])
        : `${label} (${selected.length})`;

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        aria-label={ariaLabel ?? `Filter by ${label.toLowerCase()}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={TRIGGER_CLASS}
        onClick={() => setOpen((o) => !o)}
      >
        {summary}
        <span aria-hidden="true" className="text-muted-foreground">
          ▾
        </span>
      </button>
      {open && (
        <div
          role="listbox"
          aria-multiselectable="true"
          className="absolute z-10 mt-1 max-h-64 min-w-[190px] overflow-y-auto rounded-md border border-border bg-popover p-1 shadow-md"
        >
          {options.map((o) => (
            <label
              key={o.value}
              className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs text-popover-foreground hover:bg-secondary"
            >
              <input
                type="checkbox"
                className="h-3 w-3"
                checked={selected.includes(o.value)}
                onChange={() => toggle(o.value)}
              />
              {o.label}
            </label>
          ))}
          {selected.length > 0 && (
            <button
              type="button"
              onClick={() => onChange([])}
              className="mt-1 w-full rounded px-2 py-1 text-left text-xs text-muted-foreground underline hover:text-foreground"
            >
              Clear
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Shared multi-select dropdown for the Findings page's filter bar
// (severity/fixability/tool/state/target) -- each filter param is now
// repeatable in the URL (`?severity=Critical&severity=High`), so this
// renders as a set of checkboxes rather than a single `<select>`, the
// same "URL is the source of truth" convention every other filter here
// already follows (see findings-filter-bar.tsx, group-filter.tsx).
export function MultiSelectFilter({
  label,
  paramKey,
  options,
}: {
  label: string;
  paramKey: string;
  options: MultiSelectOption[];
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const selected = searchParams.getAll(paramKey);

  function apply(next: string[]) {
    const params = new URLSearchParams(searchParams.toString());
    params.delete(paramKey);
    next.forEach((v) => params.append(paramKey, v));
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  return <MultiSelectDropdown label={label} options={options} selected={selected} onChange={apply} />;
}
