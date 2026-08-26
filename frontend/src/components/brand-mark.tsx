import { cn } from "@/lib/utils";

/**
 * Toleman wordmark/branding lockup (#116), a hex-aperture mark ("an eye on
 * terrain") replacing the generic Lucide shield-in-tile icon previously used
 * on both the sidebar and login screen. Exported as a real reusable
 * component (not inline SVG copy-pasted per screen) specifically so future
 * Login (#124) and Onboarding (#131) work can import it directly rather than
 * re-deriving the mark.
 *
 * Colors are intentionally NOT hardcoded hex, the gradient stops and inner
 * dot resolve to the theme's `--primary`/`--sidebar` custom properties (see
 * globals.css, #115) via `currentColor`/CSS var references, so the mark
 * stays correct in both light and dark without a second copy.
 */
export function BrandMark({
  size = 34,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 40 40"
      width={size}
      height={size}
      fill="none"
      className={cn("shrink-0 text-primary", className)}
      role="img"
      aria-label="Toleman"
    >
      <defs>
        <linearGradient id="toleman-brand-mark-gradient" x1="0" y1="0" x2="40" y2="40">
          <stop offset="0" stopColor="currentColor" stopOpacity="0.85" />
          <stop offset="1" stopColor="currentColor" stopOpacity="0.55" />
        </linearGradient>
      </defs>
      <path
        d="M20 2 L36 11 V29 L20 38 L4 29 V11 Z"
        stroke="url(#toleman-brand-mark-gradient)"
        strokeWidth="2.4"
        fill="currentColor"
        fillOpacity="0.08"
      />
      <path d="M20 13 L28 20 L20 27 L12 20 Z" fill="url(#toleman-brand-mark-gradient)" />
      <circle cx="20" cy="20" r="3" className="fill-background" />
    </svg>
  );
}

/** Full lockup: mark + wordmark + tagline, used in the sidebar header. */
export function BrandLockup({
  className,
  markSize = 34,
}: {
  className?: string;
  markSize?: number;
}) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <BrandMark size={markSize} />
      {/* The two lines were `gap-0` + `leading-none`, which jammed the
          wordmark onto the tagline with no breathing room. The tagline also
          carried tracking-[0.16em], whose trailing letter-space is rendered
          after the final "N"; so the block sat visibly left of the
          wordmark's optical centre. Slightly tighter tracking plus a
          matching negative right margin cancels that trailing space, and a
          2px gap separates the lines without loosening either. */}
      <div className="flex flex-col gap-[2px]">
        <span className="text-[16px] font-extrabold leading-none tracking-tight text-sidebar-foreground">
          Toleman
        </span>
        <span className="-mr-[0.13em] font-mono text-[9px] font-medium uppercase leading-none tracking-[0.13em] text-accent-strong">
          Security Terrain
        </span>
      </div>
    </div>
  );
}
