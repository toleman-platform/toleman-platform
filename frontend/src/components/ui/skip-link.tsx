import { cn } from "@/lib/utils";

/**
 * Jump-to-content link for keyboard users (WCAG 2.4.1 Bypass Blocks).
 *
 * core lows: nothing in the app plays this role today, so a keyboard user
 * lands on every page load at the top of the sidebar and has to tab through
 * the full nav -- Sidebar's every link, every collapsible section -- before
 * reaching whatever they actually came for. This is the standard fix:
 * visually hidden (`sr-only`) until it receives focus, at which point it is
 * the very first thing Tab reaches and the very first thing on screen, so
 * "skip the nav" is one keypress instead of a dozen.
 *
 * Not mounted anywhere yet. Wiring it in is two edits outside this
 * component's own scope: render `<SkipLink targetId="main-content" />` as
 * the first child of `<body>` in app/layout.tsx, and give the `<main>` in
 * app/(dashboard)/layout.tsx an `id="main-content"` (and a `tabIndex={-1}`,
 * so focus can land on a plain `<main>` that isn't otherwise focusable) to
 * match.
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
