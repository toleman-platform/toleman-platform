"use client";

import * as React from "react";
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
 *    PR History's repo/scope picker) -- `DocGenStep` for each field.
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

export function WhatsIncludedCard({
  items,
  footnote,
  className,
}: {
  items: string[];
  footnote?: string;
  className?: string;
}) {
  return (
    <Card className={cn("border-border bg-card", className)}>
      <CardContent className="flex flex-col gap-2 px-6 py-5">
        <h2 className="text-sm font-semibold text-foreground">What&apos;s included</h2>
        <ul className="list-disc pl-5 text-sm text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        {footnote && <p className="text-xs text-muted-foreground">{footnote}</p>}
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
   * generate action -- e.g. PR History's repo picker doesn't produce a
   * downloadable document, it filters the table rendered below it. */
  generateLabel?: string;
  onGenerate?: () => void;
  generating?: boolean;
  generateDisabled?: boolean;
  /** Trailing content below the generate button (stacked) or after it
   * (inline) -- e.g. SBOM's secondary "Export" action, which downloads
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
