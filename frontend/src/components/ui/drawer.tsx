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

// --- Shared modal-layer focus management ------------------------------------
//
// Drawer, ConfirmDialog and FindingDetailDialog are all the same kind of
// surface -- content stacked in front of the page that steals the keyboard
// until it's dismissed -- and until now each rolled its own (or, for this
// component, documented one it never actually built: `drawerRef` existed
// with nothing wired to it). Consolidated into one hook here rather than
// fixed three times because the interesting part isn't per-component: it's
// what happens when two of these are open at once.
//
// `layerStack` is that part. Every mounted trap pushes a token in open order
// and only the last (topmost) token's handler is allowed to act on a key
// press. Without this, opening a ConfirmDialog over the findings list (e.g.
// "delete these 12 findings?") left BOTH the dialog's own Escape listener
// and BulkActionBar's `window` Escape shortcut live at once -- one Escape
// press cancelled the dialog *and* silently cleared the selection it was
// asking about. Native keydown events bubble element -> document -> window,
// every trap here listens on `document`, and the topmost one calls
// `stopPropagation()` -- so a lower trap layer (if any) and any unrelated
// `window` listener behind the stack never see the key at all.
const layerStack: symbol[] = [];

// No offsetParent/visibility filtering here on purpose: jsdom (this repo's
// test environment) never computes layout, so an offsetParent-based check
// would silently return zero focusable elements under every test and this
// trap would be unverifiable. None of the three call sites hide focusable
// descendants inside an *open* dialog, so the plain selector is enough.
function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )
  );
}

/**
 * Traps Tab/Shift+Tab inside `containerRef` and owns Escape for whichever
 * layer is topmost, for as long as `active` is true. On activation, focuses
 * `initialFocusRef` if given (ConfirmDialog passes its Cancel button here --
 * see confirm-dialog.tsx) or the container's first focusable element
 * otherwise; on deactivation, restores focus to whatever had it before.
 *
 * `onEscape` is read through a ref rather than placed in the effect's
 * dependency array: every call site here passes a fresh inline closure on
 * every render (`() => setOpen(false)` and similar), and re-running the
 * activation effect on every unrelated re-render would re-focus the initial
 * element and yank focus out from under, e.g., someone typing in a field
 * elsewhere in the same open dialog.
 */
export function useFocusTrap({
  active,
  onEscape,
  containerRef,
  initialFocusRef,
}: {
  active: boolean;
  onEscape: () => void;
  containerRef: React.RefObject<HTMLElement | null>;
  initialFocusRef?: React.RefObject<HTMLElement | null>;
}) {
  const onEscapeRef = useRef(onEscape);
  useEffect(() => {
    onEscapeRef.current = onEscape;
  }, [onEscape]);

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    const token = Symbol("focus-trap-layer");
    layerStack.push(token);

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const toFocus = initialFocusRef?.current ?? getFocusableElements(container)[0] ?? container;
    toFocus.focus();

    // An arrow const, not a hoisted `function` declaration: TypeScript will
    // not carry the `if (!container) return` narrowing above into a hoisted
    // declaration, because such a function could in principle be called
    // before the guard runs. As a const initialised after the guard, it keeps
    // the narrowing and `container` stays HTMLElement throughout.
    const onKeyDown = (e: KeyboardEvent) => {
      const isTopmost = layerStack[layerStack.length - 1] === token;
      if (!isTopmost) return;

      if (e.key === "Escape") {
        e.stopPropagation();
        onEscapeRef.current();
        return;
      }

      if (e.key === "Tab") {
        const focusable = getFocusableElements(container);
        if (focusable.length === 0) {
          e.preventDefault();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const current = document.activeElement;
        // Wrap at either end, and also pull focus back in if it somehow
        // escaped the container (e.g. autofocus elsewhere firing after
        // this trap's own initial focus) rather than letting Tab move it
        // further away.
        if (e.shiftKey && (current === first || !container.contains(current))) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && (current === last || !container.contains(current))) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      const idx = layerStack.indexOf(token);
      if (idx !== -1) layerStack.splice(idx, 1);
      if (previouslyFocused && document.contains(previouslyFocused)) {
        previouslyFocused.focus();
      }
    };
  }, [active, containerRef, initialFocusRef]);
}

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

  // core M2: this doc comment promised focus trapping and `drawerRef` was
  // declared for it, but nothing ever used the ref -- Tab could walk focus
  // straight out of an open drawer onto the page scrolled (invisibly, since
  // body scroll is locked below) behind it. See useFocusTrap above.
  useFocusTrap({ active: open, onEscape: onClose, containerRef: drawerRef });

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
      className="fixed inset-0 z-50 flex justify-end bg-background/80 backdrop-blur-xs transition-opacity animate-in fade-in motion-reduce:animate-none motion-reduce:transition-none"
      onClick={onClose}
    >
      <div
        ref={drawerRef}
        onClick={(e) => e.stopPropagation()}
        className={cn(
          "relative flex h-full w-full flex-col border-l border-dialog-edge bg-card text-card-foreground shadow-2xl transition-transform duration-200 ease-out animate-in slide-in-from-right motion-reduce:animate-none motion-reduce:transition-none",
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
