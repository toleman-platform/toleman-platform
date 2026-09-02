"use client";

import { Target } from "@/lib/api";

// Target ids are positive (DB serial starting at 1), so 0 is a safe sentinel
// for "All repositories" without needing a separate string/number union type.
export const ALL_TARGETS = 0;

export function TargetPicker({
  targets,
  value,
  onChange,
  allowAll = false,
  label = "Repository",
}: {
  targets: Target[];
  value: number | null;
  onChange: (id: number) => void;
  allowAll?: boolean;
  /** Accessible name for the select, callers that render a visible
   * heading instead of a <label> should pass what that heading says. */
  label?: string;
}) {
  return (
    <select
      className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
      aria-label={label}
      value={value ?? ""}
      onChange={(e) => onChange(Number(e.target.value))}
    >
      <option value="" disabled>
        Select a target...
      </option>
      {allowAll && <option value={ALL_TARGETS}>All repositories</option>}
      {targets.map((t) => (
        <option key={t.id} value={t.id}>
          {t.name}
        </option>
      ))}
    </select>
  );
}
