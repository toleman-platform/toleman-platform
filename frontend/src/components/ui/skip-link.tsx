import { cn } from "@/lib/utils";

/**
 * Keyboard skip-to-content link (WCAG 2.4.1), hidden until focused. Mount first in body
 * and match targetId to a main landmark with tabIndex=-1 so focus can move there.
 */
export function SkipLink({
  targetId,
  children = "Skip to main content",
  className,
}: {
  /** id of the landmark this jumps to, e.g. the page's `<main>`. */
  targetId: string;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <a
      href={`#${targetId}`}
      className={cn(
        // `sr-only` until focused, then pinned to the corner over
        // everything else on the page -- the same shape findings-filter-bar
        // uses for its "Sort" label (`sr-only sm:not-sr-only`), just gated
        // on focus instead of viewport width.
        "sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:border focus:border-border focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:shadow-lg focus:outline-none focus-visible:ring-ring/50 focus-visible:ring-[3px]",
        className,
      )}
    >
      {children}
    </a>
  );
}
