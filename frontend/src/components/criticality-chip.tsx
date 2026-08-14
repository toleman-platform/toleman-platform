import { cn } from "@/lib/utils";

// Issue #117: a target's criticality (`Target.label` -- see
// backend/app/models/models.py) was plain text with no visual salience, so a
// Prod-labeled target read no differently from a Dev one. The audit found
// three real tiers in use -- Prod, Internal, Dev -- each mapped to its own
// color family (destructive/red, muted/slate, success/green) via the app's
// existing design tokens (frontend/src/app/globals.css), not new hardcoded
// hex. A target can also carry a free-text custom label (see the model's own
// comment: "Prod, Dev, Internal, Public, or custom") -- anything outside the
// three known tiers falls back to a neutral outline chip rather than
// guessing a risk color for it.
//
// Reused verbatim (not re-implemented) by #120 (Scans) and #125 (Targets/
// Target Detail).
const CRITICALITY_STYLE: Record<string, string> = {
  Prod: "border-destructive/30 bg-destructive/10 text-destructive",
  Internal: "border-border bg-muted text-muted-foreground",
  Dev: "border-chart-5/30 bg-chart-5/10 text-chart-5",
};

export function CriticalityChip({ label, className }: { label: string; className?: string }) {
  const style = CRITICALITY_STYLE[label] ?? "border-border bg-secondary text-secondary-foreground";
  return (
    <span
      title={`Target criticality: ${label}`}
      className={cn(
        "inline-flex shrink-0 items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wide",
        style,
        className,
      )}
    >
      {label}
    </span>
  );
}
