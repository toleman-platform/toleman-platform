import { pixelToRem } from "@/lib/utils";

/**
 * ============================================================================
 * TOLEMAN SPATIAL GRID & RADIUS TOKENS (Single Source of Truth)
 * ============================================================================
 * All 4px / 8px spatial steps and concentric corner radius tokens
 * are mathematically derived using pixelToRem on the standard 16px baseline.
 */

/** 4px / 8px Base Spatial Steps */
export const SPATIAL_SCALE = {
  "3xs": { px: 2, rem: pixelToRem(2), name: "--space-3xs", usage: "Micro borders, hairpins" },
  "2xs": { px: 4, rem: pixelToRem(4), name: "--space-2xs", usage: "Icon + text inline gaps" },
  xs: { px: 8, rem: pixelToRem(8), name: "--space-xs", usage: "Chip lists & input padding" },
  sm: { px: 12, rem: pixelToRem(12), name: "--space-sm", usage: "Compact row insets" },
  md: { px: 16, rem: pixelToRem(16), name: "--space-md", usage: "Default card internal padding" },
  lg: { px: 20, rem: pixelToRem(20), name: "--space-lg", usage: "Section header gutters" },
  xl: { px: 24, rem: pixelToRem(24), name: "--space-xl", usage: "Major component margins" },
  "2xl": { px: 32, rem: pixelToRem(32), name: "--space-2xl", usage: "Section stack separation" },
  "3xl": { px: 48, rem: pixelToRem(48), name: "--space-3xl", usage: "Page section breaks" },
} as const;

/** Concentric Corner Radii (R_outer = R_inner + padding) */
export const RADIUS_SCALE = {
  xs: { px: 4, rem: pixelToRem(4), name: "--radius-xs", usage: "Micro tags, status chips" },
  sm: { px: 6, rem: pixelToRem(6), name: "--radius-sm", usage: "Badges, code pills" },
  md: { px: 8, rem: pixelToRem(8), name: "--radius-md", usage: "Inner interactive controls, buttons" },
  lg: { px: 12, rem: pixelToRem(12), name: "--radius-lg", usage: "Standard cards, dropdown panels" },
  xl: { px: 16, rem: pixelToRem(16), name: "--radius-xl", usage: "Page containers, modal sheets" },
} as const;

/** Density Row/Page Padding Tokens */
export const DENSITY_TOKENS = {
  comfortable: {
    rowPy: { px: 12, rem: pixelToRem(12) },
    pagePy: { px: 32, rem: pixelToRem(32) },
    gap: { px: 24, rem: pixelToRem(24) },
    listGap: { px: 8, rem: pixelToRem(8) },
  },
  compact: {
    rowPy: { px: 6, rem: pixelToRem(6) },
    pagePy: { px: 20, rem: pixelToRem(20) },
    gap: { px: 16, rem: pixelToRem(16) },
    listGap: { px: 4, rem: pixelToRem(4) },
  },
} as const;
