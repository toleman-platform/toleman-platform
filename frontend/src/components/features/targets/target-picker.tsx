"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { Target } from "@/lib/api";

// Target ids are positive (DB serial starting at 1), so 0 is a safe sentinel
// for "All repositories" without needing a separate string/number union type.
export const ALL_TARGETS = 0;

/**
 * Searchable, multi-select repository picker. Renders as a button that opens
 * a checkbox listbox with a text filter at the top -- the native `<select>`
 * this replaced had no way to filter and no way to pick more than one, which
 * stopped scaling once a workspace had more than a handful of repos (#520).
 *
 * `value`/`onChange` are always arrays, even for a caller that only ever
 * wants one repo selected at a time -- `value[0]` reads the single choice,
 * and `onChange([id])` sets it. When `allowAll` is set, `ALL_TARGETS` (0) can
 * appear in `value` as its own pseudo-selection representing every repo;
 * picking it clears any specific ids, and picking a specific repo while "All
 * repositories" is active replaces it rather than adding to it.
 */
export function TargetPicker({
  targets,
  value,
  onChange,
  allowAll = false,
  label = "Repository",
  placeholder = "Search repositories...",
}: {
  targets: Target[];
  value: number[];
  onChange: (ids: number[]) => void;
  allowAll?: boolean;
  /** Accessible name for the control, callers that render a visible
   * heading instead of a <label> should pass what that heading says. */
  label?: string;
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery("");
      }
    }
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  useEffect(() => {
    if (open) searchRef.current?.focus();
  }, [open]);

  const isAll = allowAll && value.includes(ALL_TARGETS);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter((t) => t.name.toLowerCase().includes(q));
  }, [targets, query]);

  function toggle(id: number) {
    if (isAll) {
      onChange([id]);
      return;
    }
    onChange(value.includes(id) ? value.filter((v) => v !== id) : [...value, id]);
  }

  const selectedTargets = targets.filter((t) => value.includes(t.id));
  const summary = isAll
    ? "All repositories"
    : selectedTargets.length === 0
      ? "Select repositories…"
      : selectedTargets.length === 1
        ? selectedTargets[0].name
        : `${selectedTargets.length} repositories`;

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex h-9 min-w-[200px] items-center justify-between gap-2 rounded-md border border-input bg-secondary px-3 text-sm text-foreground"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="truncate">{summary}</span>
        <span aria-hidden="true" className="shrink-0 text-muted-foreground">
          ▾
        </span>
      </button>
      {open && (
        <div className="absolute z-10 mt-1 w-72 max-w-[90vw] rounded-md border border-border bg-popover shadow-md">
          <div className="flex items-center gap-2 border-b border-border px-2 py-1.5">
            <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
            <input
              ref={searchRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={placeholder}
              aria-label={`Search ${label.toLowerCase()}`}
              className="w-full bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
          <div role="listbox" aria-multiselectable="true" aria-label={label} className="max-h-64 overflow-y-auto p-1">
            {allowAll && (
              <label className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs text-popover-foreground hover:bg-secondary">
                <input
                  type="checkbox"
                  className="h-3 w-3"
                  checked={isAll}
                  onChange={() => onChange(isAll ? [] : [ALL_TARGETS])}
                />
                All repositories
              </label>
            )}
            {filtered.map((t) => (
              <label
                key={t.id}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs text-popover-foreground hover:bg-secondary"
              >
                <input
                  type="checkbox"
                  className="h-3 w-3"
                  checked={!isAll && value.includes(t.id)}
                  onChange={() => toggle(t.id)}
                />
                <span className="truncate">{t.name}</span>
              </label>
            ))}
            {filtered.length === 0 && (
              <p className="px-2 py-3 text-center text-xs text-muted-foreground">
                No repositories match &quot;{query}&quot;
              </p>
            )}
          </div>
          {value.length > 0 && (
            <div className="border-t border-border p-1">
              <button
                type="button"
                onClick={() => onChange([])}
                className="w-full rounded px-2 py-1 text-left text-xs text-muted-foreground underline hover:text-foreground"
              >
                Clear
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
