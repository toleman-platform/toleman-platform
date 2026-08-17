import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";

/**
 * A density-aware row in a scannable list (issue #210).
 *
 * Four files repeated the same two lines:
 *
 *     <Card className="... py-0">
 *       <CardContent style={{ paddingTop: "var(--density-row-py)",
 *                             paddingBottom: "var(--density-row-py)" }}>
 *
 * The `py-0` is not cosmetic. The base Card carries `py-6` -- 48px that no
 * density token can reach -- so a row without it ignores the density setting
 * almost entirely. That was the actual cause of "Compact only saves 7%" in
 * #172, and the fix had to be applied file by file. Putting it here means the
 * next list gets it for free instead of reintroducing the bug.
 *
 * `selectable` renders the checkbox rather than leaving each list to place
 * its own, because the accessible name is the part everyone forgets: a column
 * of unlabelled checkboxes is announced as "checkbox, checkbox, checkbox"
 * with no indication of what is being selected.
 */
export type ListRowProps = {
  children: React.ReactNode;
  /** Left border accent, e.g. severity. Pass a border-colour utility. */
  accentClassName?: string;
  selectable?: boolean;
  selected?: boolean;
  onSelectChange?: (checked: boolean) => void;
  /** Names the row for assistive tech: "Select finding <title>". Required
   * whenever `selectable` is set -- an unnamed checkbox is not usable. */
  selectLabel?: string;
  /** Hover affordance for a row that navigates somewhere. */
  interactive?: boolean;
  className?: string;
};

export function ListRow({
  children,
  accentClassName,
  selectable = false,
  selected = false,
  onSelectChange,
  selectLabel,
  interactive = false,
  className,
}: ListRowProps) {
  if (process.env.NODE_ENV !== "production" && selectable && !selectLabel) {
    // Loud in development, silent in production: a missing accessible name is
    // a real defect, but not one worth breaking a user's page over.
    console.warn("ListRow: `selectable` requires `selectLabel` so the checkbox has an accessible name.");
  }

  return (
    <Card
      interactive={interactive}
      className={cn(
        "border-border bg-card py-0",
        accentClassName && `border-l-4 ${accentClassName}`,
        className,
      )}
    >
      <CardContent
        className="flex items-center gap-3 px-4"
        style={{ paddingTop: "var(--density-row-py)", paddingBottom: "var(--density-row-py)" }}
      >
        {selectable && (
          <input
            type="checkbox"
            aria-label={selectLabel}
            className="h-4 w-4 shrink-0 accent-primary"
            checked={selected}
            onChange={(e) => onSelectChange?.(e.target.checked)}
            // Without this a click on the checkbox also triggers the row's
            // own navigation, so selecting a row navigates away from the list.
            onClick={(e) => e.stopPropagation()}
          />
        )}
        {children}
      </CardContent>
    </Card>
  );
}

/**
 * Vertical stack for ListRows, with the inter-row gap tracking density.
 *
 * At 25 rows an 8px gap is 200px of extra scroll on a page whose entire
 * purpose is scanning a list, so the gap is a density token rather than a
 * constant (#172).
 */
export function ListRows({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col", className)} style={{ gap: "var(--density-list-gap)" }}>
      {children}
    </div>
  );
}

/**
 * The header control that selects every row on the current page.
 *
 * Wired to `useSelection`'s `allVisibleSelected` / `someVisibleSelected`.
 * `indeterminate` is a DOM property with no JSX attribute, so it has to be
 * set through a ref -- which is exactly the kind of detail that gets skipped
 * when each list rolls its own, leaving a half-selected page showing an
 * unticked box.
 */
export function SelectAllVisible({
  allSelected,
  someSelected,
  onChange,
  label = "Select all on this page",
  count,
}: {
  allSelected: boolean;
  someSelected: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  /** Optional trailing context, e.g. "12 of 35 match". */
  count?: string;
}) {
  const ref = React.useRef<HTMLInputElement>(null);
  React.useEffect(() => {
    if (ref.current) ref.current.indeterminate = someSelected && !allSelected;
  }, [someSelected, allSelected]);

  return (
    <label className="flex w-fit cursor-pointer items-center gap-2 text-xs text-muted-foreground">
      <input
        ref={ref}
        type="checkbox"
        className="h-4 w-4 accent-primary"
        checked={allSelected}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        {count ? ` (${count})` : ""}
      </span>
    </label>
  );
}
