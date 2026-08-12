"use client";

import { Target } from "@/lib/api";

export function TargetPicker({
  targets,
  value,
  onChange,
}: {
  targets: Target[];
  value: number | null;
  onChange: (id: number) => void;
}) {
  return (
    <select
      className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
      value={value ?? ""}
      onChange={(e) => onChange(Number(e.target.value))}
    >
      <option value="" disabled>
        Select a target...
      </option>
      {targets.map((t) => (
        <option key={t.id} value={t.id}>
          {t.name}
        </option>
      ))}
    </select>
  );
}
