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
  label,
}: {
  value: EnforcementMode | null;
  onChange: (mode: EnforcementMode | null) => void;
  disabled?: boolean;
  className?: string;
  inheritLabel?: string;
  /**
   * Accessible name for this particular control. A page that renders one of
   * these per group gave every one of them the identical "Enforcement mode"
   * name, so a screen-reader user tabbing the list could not tell which
   * group's setting they were about to change. Callers in a list must pass
   * something that identifies the row, e.g. `Enforcement mode for production`.
   */
  label?: string;
}) {
  return (
    <select
      aria-label={label ?? "Enforcement mode"}
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

/**
 * What each mode actually does to a pull request. The three options were bare
 * one-word labels everywhere they appeared, with no statement anywhere in the
 * UI of the difference between them -- so the control that decides whether a
 * Critical finding stops a merge was unexplained at the point of change.
 * Stated once here and rendered wherever the select is offered.
 */
export const ENFORCEMENT_MODE_HELP: Record<EnforcementMode, string> = {
  block: "PR Guardrail posts its findings and fails the check, so the PR can't merge until they're fixed, ignored with approval, or overridden.",
  alert: "PR Guardrail posts its findings as a comment and passes the check. Nothing is blocked.",
  disabled: "PR Guardrail doesn't run on pull requests at all. Nothing is posted and nothing is checked.",
};

/** Platform fallback when neither the target, its groups, nor the workspace set a mode. */
export const DEFAULT_ENFORCEMENT_MODE: EnforcementMode = "block";

/**
 * Resolve what a row will actually do, given its own override and the mode it
 * inherits from. Kept next to the select because "Inherit" on its own is not
 * a legible answer to "what happens to my PR?".
 */
export function resolveEnforcementMode(
  own: EnforcementMode | null,
  inheritedFrom: EnforcementMode | null,
): EnforcementMode {
  return own ?? inheritedFrom ?? DEFAULT_ENFORCEMENT_MODE;
}

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
