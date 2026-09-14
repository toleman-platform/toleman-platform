"use client";

import { useRef } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useFocusTrap } from "@/components/ui/drawer";

export type ConfirmDialogProps = {
  open: boolean;
  title: string;
  description: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** "destructive" (red, delete/remove-type actions) vs "default" (e.g. role escalation, consequential but not a delete). */
  tone?: "destructive" | "default";
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

// Reusable confirmation dialog for destructive actions (delete) and other
// consequential-but-reversible changes (e.g. admin-role escalation),
// issue #118. No radix-dialog dependency in this repo yet, so this is a
// small self-contained modal: overlay + centered card, Escape/backdrop-click
// to cancel, focus trapped inside and moved to Cancel (not Confirm) on open.
// Render at the call site with `open` gating so unmounted state never
// renders a floating invisible dialog.
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "destructive",
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  // admin L8: this used to autofocus Confirm. These dialogs exist
  // specifically to gate destructive/consequential actions -- delete an SLA
  // rule, revoke a key, downgrade enforcement -- so a keyboard user who
  // opens one and reflexively hits Enter must land on Cancel, not on the
  // action the dialog exists to double-check. `initialFocusRef` below is
  // what makes that Cancel instead of the container's first focusable child
  // (which would have been Cancel anyway here, but only by DOM-order
  // accident; naming it is the actual fix).
  //
  // core M3 / admin L7: focus trap + centralized Escape, shared with Drawer
  // and FindingDetailDialog -- see useFocusTrap in drawer.tsx for why
  // Escape is handled there instead of the `document` listener this file
  // used to own by itself (it was also dismissing whatever else was
  // listening for Escape behind this dialog, e.g. BulkActionBar's
  // selection-clear shortcut).
  useFocusTrap({
    active: open,
    onEscape: onCancel,
    containerRef,
    initialFocusRef: cancelRef,
  });

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        ref={containerRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
        className="w-full max-w-sm rounded-xl border border-border bg-card p-5 shadow-lg"
      >
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
              tone === "destructive" ? "bg-destructive/10 text-destructive" : "bg-primary/10 text-accent-strong"
            )}
          >
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div className="flex flex-col gap-1">
            <div id="confirm-dialog-title" className="font-medium text-foreground">
              {title}
            </div>
            <div id="confirm-dialog-description" className="text-sm text-muted-foreground">
              {description}
            </div>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button ref={cancelRef} variant="outline" size="sm" onClick={onCancel} disabled={loading}>
            {cancelLabel}
          </Button>
          <Button
            variant={tone === "destructive" ? "destructive" : "default"}
            size="sm"
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? "Working..." : confirmLabel}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  );
}
