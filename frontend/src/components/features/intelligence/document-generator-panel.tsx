"use client";

import * as React from "react";
import { ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Shared "pick a target, generate/scope a thing" panel (issue #121).
 * Previously SBOM, API Discovery and PR History each hand-rolled their own
 * selector markup at three different widths/styles. This is the single
 * implementation all four pages (SBOM, API Discovery, PR History, Reports)
 * now build on, matching the design board's `doc-gen` panel:
 *
 *  - "stacked" layout: numbered vertical steps (SBOM, API Discovery,
 *    PR History's repo/scope picker), `DocGenStep` for each field.
 *  - "inline" layout: a single horizontal row (Reports' own pre-existing
 *    best-in-app shape, kept close to as-is per the design board) --
 *    `DocGenField` for each field.
 *
 * `WhatsIncludedCard` is exported separately (not just used internally) so
 * Reports, whose content card renders outside the selector card, can share
 * the exact same markup instead of a near-duplicate.
 */

export function DocGenStep({
  n,
  label,
  children,
}: {
  n: number;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[10px] font-semibold text-accent-strong">
          {n}
        </span>
        {label}
      </label>
      {children}
    </div>
  );
}

export function DocGenField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-medium text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}

export type DocGenOption = {
  value: string;
  label: string;
  disabled?: boolean;
};

export function DocGenToggle({
  options,
  value,
  onChange,
}: {
  options: DocGenOption[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1 rounded-md border border-input bg-secondary p-1">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => !o.disabled && onChange(o.value)}
          disabled={o.disabled}
          className={cn(
            "rounded px-3 py-1.5 text-xs font-medium uppercase tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-40",
            value === o.value
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Single-value picker for a generator step (#302): the Reports page's repo
 * group / environment / owner / category filters. Same markup as the
 * Findings page's own single-value filters (see group-filter.tsx), but
 * driven by local state rather than a search param, since a report builder
 * is a form the operator submits, not a view whose state belongs in the URL.
 *
 * `placeholder` is the "no filter" option and always maps to "", so an
 * un-set filter is a real, re-selectable choice rather than a one-way door.
 */
export function DocGenSelect({
  value,
  onChange,
  options,
  placeholder,
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  options: DocGenOption[];
  placeholder: string;
  ariaLabel: string;
}) {
  return (
    <select
      aria-label={ariaLabel}
      className="h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o.value} value={o.value} disabled={o.disabled}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

/**
 * What the reader will get if they press Generate, as a disclosure that is
 * closed until asked for.
 *
 * A disclosure rather than folding this into the page heading's `HelpHint`,
 * for two reasons. The Reports call site's list is not fixed copy -- it is
 * the sections the operator has actually ticked, plus a footnote naming the
 * ones they excluded -- and `HelpHint` takes a static `HelpTopic` from the
 * shared help registry, so that content has nowhere to live there. And the
 * two answer different questions: the help hint says what this page is for,
 * while this says what the button next to it will produce, which is why it
 * belongs beside the button.
 *
 * Closed by default because the answer stops being news after the first
 * generation, and an always-open list of three or four bullets was taking a
 * large share of the viewport on every subsequent visit, forever.
 */
export function WhatsIncludedCard({
  items,
  footnote,
  className,
}: {
  items: string[];
  footnote?: string;
  className?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const panelId = React.useId();

  return (
    <Card className={cn("border-border bg-card py-0", className)}>
      <CardContent className="flex flex-col gap-2 px-5 py-3">
        {/* The trigger sits inside the heading rather than replacing it, so
            the section is still a stop for heading navigation when closed. */}
        <h2 className="text-sm font-semibold">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={open ? panelId : undefined}
            onClick={() => setOpen((v) => !v)}
            className="flex w-full items-center gap-1.5 text-left text-foreground hover:text-accent-strong"
          >
            <ChevronRight
              aria-hidden="true"
              className={cn("size-3.5 shrink-0 transition-transform", open && "rotate-90")}
            />
            What&apos;s included
          </button>
        </h2>
        {open && (
          <div id={panelId} className="flex flex-col gap-2">
            <ul className="list-disc pl-5 text-sm text-muted-foreground">
              {items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            {footnote && <p className="text-xs text-muted-foreground">{footnote}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function DocumentGeneratorPanel({
  layout = "stacked",
  steps,
  generateLabel,
  onGenerate,
  generating = false,
  generateDisabled = false,
  extra,
  className,
}: {
  /** "stacked": numbered vertical steps. "inline": single horizontal row. */
  layout?: "stacked" | "inline";
  steps: React.ReactNode[];
  /** Omit both to render the panel purely as a scope filter with no
   * generate action, e.g. PR History's repo picker doesn't produce a
   * downloadable document, it filters the table rendered below it. */
  generateLabel?: string;
  onGenerate?: () => void;
  generating?: boolean;
  generateDisabled?: boolean;
  /** Trailing content below the generate button (stacked) or after it
   * (inline), e.g. SBOM's secondary "Export" action, which downloads
   * already-persisted data independent of the "Generate" scan trigger. */
  extra?: React.ReactNode;
  className?: string;
}) {
  const showButton = !!generateLabel && !!onGenerate;

  if (layout === "inline") {
    return (
      <Card className={cn("border-border bg-card", className)}>
        <CardContent className="flex flex-wrap items-end gap-3 px-6 py-5">
          {steps}
          {showButton && (
            <Button onClick={onGenerate} disabled={generating || generateDisabled} className="ml-auto">
              {generating ? "Generating..." : generateLabel}
            </Button>
          )}
          {extra}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("border-border bg-card", className)}>
      <CardContent className="flex flex-col gap-4 px-5 py-5">
        {steps}
        {showButton && (
          <Button onClick={onGenerate} disabled={generating || generateDisabled} className="w-full justify-center">
            {generating ? "Generating..." : generateLabel}
          </Button>
        )}
        {extra}
      </CardContent>
    </Card>
  );
}
