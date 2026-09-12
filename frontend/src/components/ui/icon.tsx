import * as React from "react";
import { cn } from "@/lib/utils";
import type { LucideIcon, LucideProps } from "lucide-react";

export type IconSize = "xs" | "sm" | "md" | "lg" | "xl" | "2xl" | number;
export type IconTone = "default" | "muted" | "primary" | "destructive" | "warning" | "success" | "accent";

export interface IconProps extends Omit<React.SVGProps<SVGSVGElement>, "size"> {
  /** The icon component to render (e.g. Lucide icon) */
  icon?: LucideIcon | React.ComponentType<LucideProps>;
  /** Standard semantic size variant or custom numeric pixel value (defaults to 'md' = 16px) */
  size?: IconSize;
  /** Semantic color tone */
  tone?: IconTone;
  /** Accessible label. If provided, role="img" is set; otherwise marked aria-hidden="true" */
  label?: string;
  /** Pass-through child icon if used as a wrapper */
  children?: React.ReactNode;
}

const SIZE_CLASSES: Record<"xs" | "sm" | "md" | "lg" | "xl" | "2xl", { className: string; px: number }> = {
  xs: { className: "h-3 w-3", px: 12 },
  sm: { className: "h-3.5 w-3.5", px: 14 },
  md: { className: "h-4 w-4", px: 16 },
  lg: { className: "h-5 w-5", px: 20 },
  xl: { className: "h-6 w-6", px: 24 },
  "2xl": { className: "h-8 w-8", px: 32 },
};

const TONE_CLASSES: Record<IconTone, string> = {
  default: "text-current",
  muted: "text-muted-foreground",
  primary: "text-primary",
  destructive: "text-destructive",
  warning: "text-warning",
  success: "text-success",
  accent: "text-accent-strong",
};

/**
 * Standardized Icon Wrapper Component.
 * Enforces consistent sizing, semantic colors, and accessibility across all UI views.
 *
 * Usage:
 * - `<Icon icon={ShieldAlert} size="md" tone="primary" />`
 * - `<Icon size="lg"><Settings /></Icon>`
 * - `<Icon icon={Search} size={18} label="Search database" />`
 */
export function Icon({
  icon: Component,
  size = "md",
  tone = "default",
  label,
  className,
  children,
  style,
  ...props
}: IconProps) {
  const isNamedSize = typeof size === "string" && size in SIZE_CLASSES;
  const sizeMeta = isNamedSize ? SIZE_CLASSES[size as keyof typeof SIZE_CLASSES] : null;
  const numericSize = typeof size === "number" ? size : sizeMeta?.px ?? 16;
  const sizeClass = sizeMeta?.className;

  const toneClass = TONE_CLASSES[tone] || TONE_CLASSES.default;
  const a11yProps = label
    ? { role: "img", "aria-label": label }
    : { "aria-hidden": true };

  const combinedClassName = cn(
    "shrink-0 transition-colors",
    sizeClass,
    toneClass,
    className
  );

  const customStyle: React.CSSProperties = typeof size === "number"
    ? { width: `${size}px`, height: `${size}px`, ...style }
    : { ...style };

  // 1. Direct component prop: <Icon icon={Scan} size="sm" />
  if (Component) {
    return (
      <Component
        size={numericSize}
        className={combinedClassName}
        style={customStyle}
        {...a11yProps}
        {...(props as unknown as LucideProps)}
      />
    );
  }

  // 2. Wrapped child icon: <Icon size="sm"><Scan /></Icon>
  if (React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<LucideProps>, {
      size: numericSize,
      className: cn(combinedClassName, (children.props as { className?: string }).className),
      style: { ...customStyle, ...(children.props as { style?: React.CSSProperties }).style },
      ...a11yProps,
      ...props,
    });
  }

  return null;
}
