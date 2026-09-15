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
 * A small affordance next to a heading that says, in plain language, what the
 * feature does and who it is for, plus a link to the documentation page when
 * one is published.
 *
 * Deliberately a click-triggered disclosure rather than a tooltip, for three
 * reasons that a tooltip cannot be talked out of:
 *
 *   1. Radix's TooltipTrigger returns early from its pointer handler when
 *      `pointerType === "touch"`, and separately suppresses the focus path
 *      while a pointer is down. On a phone or tablet the net effect is that
 *      tapping the trigger does nothing at all -- a visible, labelled button
 *      that is inert for every touch user.
 *   2. A tooltip closes on blur, so a "Learn more" link inside one can never
 *      be reached by keyboard: the panel is gone before focus lands on it.
 *      `role="tooltip"` also must not contain interactive elements, and Radix
 *      renders its content a second time inside a visually hidden node, which
 *      would put a duplicate link in the accessibility tree.
 *   3. Clicking a tooltip trigger closes it, and it will not reopen until the
 *      pointer leaves and returns -- so the obvious interaction with a button
 *      destroys the thing the button is for.
 *
 * A disclosure has none of those problems: it opens on click and on Enter or
 * Space, it stays open while focus moves through it, and interactive content
 * inside it is ordinary.
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
