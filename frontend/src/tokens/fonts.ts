import { Plus_Jakarta_Sans, Geist_Mono } from "next/font/google";
import { pixelToRem } from "@/lib/utils";

/**
 * ============================================================================
 * TOLEMAN CENTRALIZED TYPOGRAPHY CONFIGURATION (Single Source of Truth)
 * ============================================================================
 * Defines all font loaders, fallback font stacks, and scalable type scale tokens.
 *
 * To swap font families: edit `sansFont` or `monoFont` below.
 * To adjust global font sizes: edit `TYPE_SCALE` below or `:root` variables in `globals.css`.
 */

/** Primary Sans-Serif Font (Display, Titles, Headings, Body Copy) */
export const sansFont = Plus_Jakarta_Sans({
  variable: "--font-sans-loaded",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  display: "swap",
});

/** Primary Monospace Font (Code, Rule IDs, CVEs, Tabular Metric Gauges) */
export const monoFont = Geist_Mono({
  variable: "--font-mono-loaded",
  subsets: ["latin"],
  display: "swap",
});

/** Standard Fallback Font Stacks */
export const SANS_FALLBACK_STACK =
  'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
export const MONO_FALLBACK_STACK =
  'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';

/** Centralized Type Scale Token Dictionary (computed dynamically via pixelToRem) */
export const TYPE_SCALE = {
  display: {
    className: "text-display",
    size: "32px–40px",
    px: 36,
    rem: `clamp(${pixelToRem(32)}, 1.75rem + 1vw, ${pixelToRem(40)})`,
    weight: 800,
    tracking: "-0.025em",
    leading: "1.15",
    description: "Hero metrics and high-impact page statistics",
  },
  title: {
    className: "text-title",
    size: "22px–28px",
    px: 24,
    rem: `clamp(${pixelToRem(22)}, 1.25rem + 0.5vw, ${pixelToRem(28)})`,
    weight: 700,
    tracking: "-0.02em",
    leading: "1.25",
    description: "Main page titles and top-level entity headers",
  },
  heading: {
    className: "text-heading",
    size: "20px",
    px: 20,
    rem: pixelToRem(20),
    weight: 600,
    tracking: "-0.015em",
    leading: "1.35",
    description: "Section headings and modal titles",
  },
  subheading: {
    className: "text-subheading",
    size: "17px",
    px: 17,
    rem: pixelToRem(17),
    weight: 600,
    tracking: "-0.01em",
    leading: "1.4",
    description: "Card sub-titles and list category headers",
  },
  body: {
    className: "text-body",
    size: "15px",
    px: 15,
    rem: pixelToRem(15),
    weight: 400,
    tracking: "normal",
    leading: "1.55",
    description: "Primary readable body copy, descriptions, and drawer paragraphs",
  },
  bodySm: {
    className: "text-body-sm",
    size: "14px",
    px: 14,
    rem: pixelToRem(14),
    weight: 400,
    tracking: "normal",
    leading: "1.5",
    description: "Secondary descriptive metadata and compact card copy",
  },
  caption: {
    className: "text-caption",
    size: "13px",
    px: 13,
    rem: pixelToRem(13),
    weight: 500,
    tracking: "normal",
    leading: "1.45",
    description: "Table rows, filter chips, and interactive badges",
  },
  meta: {
    className: "text-meta",
    size: "12px",
    px: 12,
    rem: pixelToRem(12),
    weight: 500,
    tracking: "0.01em",
    leading: pixelToRem(16),
    description: "Timestamps, secondary subtitles, and auxiliary guidance",
  },
  micro: {
    className: "text-micro",
    size: "11px",
    px: 11,
    rem: pixelToRem(11),
    weight: 600,
    tracking: "0.04em",
    leading: pixelToRem(14),
    description: "All-caps labels, KEV badges, and shortcut keys (⌘K)",
  },
  code: {
    className: "text-code",
    size: "14px",
    px: 14,
    rem: pixelToRem(14),
    weight: 500,
    tracking: "-0.01em",
    leading: "1.45",
    description: "Monospace code snippets, rule IDs, and file coordinates",
  },
  metricXl: {
    className: "text-metric-xl",
    size: "34px",
    px: 34,
    rem: pixelToRem(34),
    weight: 700,
    tracking: "-0.03em",
    leading: "1.15",
    description: "XL Tabular metric numeral",
  },
  metricLg: {
    className: "text-metric-lg",
    size: "26px",
    px: 26,
    rem: pixelToRem(26),
    weight: 700,
    tracking: "-0.025em",
    leading: "1.2",
    description: "LG Tabular metric numeral",
  },
  metricMd: {
    className: "text-metric-md",
    size: "20px",
    px: 20,
    rem: pixelToRem(20),
    weight: 700,
    tracking: "-0.02em",
    leading: "1.25",
    description: "MD Tabular metric numeral",
  },
} as const;
