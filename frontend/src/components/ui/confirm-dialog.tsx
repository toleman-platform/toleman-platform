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

  // Focus Cancel explicitly for consequential actions so an immediate Enter cannot
  // confirm. Share the modal focus/Escape stack with drawers and detail dialogs to
  // prevent background listeners from firing.
  useFocusTrap({
    active: open,
    onEscape: onCancel,
    containerRef,
    initialFocusRef: cancelRef,
  });

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-overlay scrim-blur p-4"
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
        className="w-full max-w-sm material rounded-2xl border border-dialog-edge/50 p-6 animate-in zoom-in-95 fade-in duration-200 motion-reduce:animate-none"
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
