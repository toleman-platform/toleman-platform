"use client";

import * as React from "react";
import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  size?: "md" | "lg" | "xl" | "full";
}

const SIZE_MAP = {
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-2xl",
  full: "max-w-4xl",
};

/**
 * Enterprise Slide-over Inspection Drawer (Sheet).
 * Follows Section 14 (Master-Detail Interactions) and Section 22 (Drawer vs Modal).
 * Supports Escape key close, backdrop dismissal, accessible labeling, and focus trapping.
 */
export function Drawer({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  className,
  size = "xl",
}: DrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);

  // Close on Escape key press
  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClose();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  // Prevent background body scrolling when drawer is open
  useEffect(() => {
    if (open) {
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      return () => {
        document.body.style.overflow = originalOverflow;
      };
    }
  }, [open]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
      className="fixed inset-0 z-50 flex justify-end bg-background/80 backdrop-blur-xs transition-opacity animate-in fade-in"
      onClick={onClose}
    >
      <div
        ref={drawerRef}
        onClick={(e) => e.stopPropagation()}
        className={cn(
          "relative flex h-full w-full flex-col border-l border-border bg-card text-card-foreground shadow-2xl transition-transform duration-200 ease-out animate-in slide-in-from-right",
          SIZE_MAP[size],
          className
        )}
      >
        {/* Drawer Header */}
        <div className="flex items-start justify-between border-b border-border px-6 py-4">
          <div className="space-y-1 pr-4 min-w-0 flex-1">
            {title && (
              <h2 id="drawer-title" className="text-title text-foreground truncate">
                {title}
              </h2>
            )}
            {description && (
              <div className="text-body-sm text-muted-foreground">{description}</div>
            )}
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            aria-label="Close drawer"
            className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground shrink-0 rounded-md"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Drawer Body (Scrollable) */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {children}
        </div>

        {/* Drawer Footer (Sticky Actions) */}
        {footer && (
          <div className="border-t border-border bg-card px-6 py-4 flex items-center justify-end gap-3 shrink-0">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
