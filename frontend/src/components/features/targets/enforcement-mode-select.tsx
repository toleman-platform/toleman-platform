"use client";

import { EnforcementMode } from "@/lib/api";

// Issue #62: shared Inherit/Block/Alert/Disabled select, reused on the
// target detail page, the group admin UI, and the workspace-level setting.
// `value` is the raw override (null = "Inherit"); never the resolved
// effective mode, which is display-only (see EnforcementModeLabel below).
export function EnforcementModeSelect({
  value,
  onChange,
  disabled,
  className,
  inheritLabel = "Inherit",
}: {
  value: EnforcementMode | null;
  onChange: (mode: EnforcementMode | null) => void;
  disabled?: boolean;
  className?: string;
  inheritLabel?: string;
}) {
  return (
    <select
      aria-label="Enforcement mode"
      className={
        className ??
        "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground disabled:opacity-50"
      }
      value={value ?? ""}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value === "" ? null : (e.target.value as EnforcementMode))}
    >
      <option value="">{inheritLabel}</option>
      <option value="block">Block</option>
      <option value="alert">Alert</option>
      <option value="disabled">Disabled</option>
    </select>
  );
}

const MODE_LABEL: Record<EnforcementMode, string> = {
  block: "Block",
  alert: "Alert",
  disabled: "Disabled",
};

const SOURCE_LABEL: Record<string, string> = {
  target: "set directly on this target",
  group: "inherited from a group",
  workspace: "inherited from workspace",
  default: "default; nothing configured",
};

// Legibility label for the *effective* resolved mode (issue #62): "Block
// (inherited from workspace)", not just settable, but visible where it
// actually came from.
export function EnforcementModeLabel({
  mode,
  source,
}: {
  mode: EnforcementMode;
  source?: string;
}) {
  const tone =
    mode === "block"
      ? "bg-destructive/10 text-destructive border-destructive/30"
      : mode === "alert"
        ? "bg-chart-3/10 text-chart-3 border-chart-3/30"
        : "bg-muted text-muted-foreground border-border";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 font-medium ${tone}`}>
        {MODE_LABEL[mode]}
      </span>
      {source && <span>({SOURCE_LABEL[source] ?? source})</span>}
    </span>
  );
}
