"use client";

import * as React from "react";
import { ExternalLink, Info } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { HelpTopic } from "@/lib/help-content";
import { cn, safeHref } from "@/lib/utils";

export interface HelpHintProps {
  /** What the hint explains. Shared copy lives in `@/lib/help-content`. */
  topic: HelpTopic;
  /** Which side of the trigger the panel opens on. */
  side?: "bottom" | "top";
  className?: string;
}

/**
 * Use a click/keyboard disclosure for contextual help and documentation links. Tooltips
 * cannot reliably serve touch users or contain keyboard-reachable interactive links.
 * Keep the panel open while focus moves through its content.
 */
export function HelpHint({ topic, side = "bottom", className }: HelpHintProps) {
  const { title, body, docsUrl } = topic;
  const docsHref = safeHref(docsUrl);
  const [open, setOpen] = React.useState(false);
  const panelId = React.useId();
  const containerRef = React.useRef<HTMLSpanElement | null>(null);
  const triggerRef = React.useRef<HTMLButtonElement | null>(null);

  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setOpen(false);
      // Focus would otherwise be left on a node that is no longer rendered,
      // which drops a keyboard user back to the top of the document.
      triggerRef.current?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <span ref={containerRef} className={cn("relative inline-flex", className)}>
      <Button
        ref={triggerRef}
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-label={`About ${title}`}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={() => setOpen((v) => !v)}
        className="size-6 rounded-full text-muted-foreground hover:text-foreground"
      >
        {/* `Info`, not `HelpCircle`: this design system already assigns
            HelpCircle the meaning "Unknown" on StatusBadge, and a muted
            HelpCircle beside a page title would read as a status next to the
            same glyph meaning a status in the rows below it. */}
        <Info className="size-3.5" aria-hidden="true" />
      </Button>
      {open && (
        <span
          id={panelId}
          role="group"
          aria-label={title}
          className={cn(
            "absolute z-50 w-64 rounded-md border border-border bg-popover p-3 text-left text-xs shadow-md",
            side === "bottom" ? "top-full mt-1" : "bottom-full mb-1",
            "left-0",
          )}
        >
          <span className="block font-medium text-popover-foreground">{title}</span>
          <span className="mt-1 block text-muted-foreground">{body}</span>
          {docsHref && (
            <a
              href={docsHref}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-foreground underline underline-offset-2"
            >
              Learn more
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          )}
        </span>
      )}
    </span>
  );
}
