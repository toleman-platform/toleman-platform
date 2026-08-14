"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

// Issue #117: reusable truncation-with-tooltip affordance -- any place a
// long label gets clipped with CSS `truncate` should render it through this
// instead of a bare `<span className="truncate">`, so hovering (or focusing,
// for keyboard users) reveals the full text instead of the value silently
// disappearing. A dashed underline is the visual "there's more here" cue
// (mirrors the #117 design board's `.title-trunc` treatment). `title` is
// also set as a native attribute so long-press/assistive tech still surfaces
// the full text even before the Radix tooltip mounts.
//
// Reused verbatim (not re-implemented) by #119 (Dashboard recent findings).
export function TruncateTooltip({
  text,
  subtext,
  className,
  as: Component = "span",
  contentClassName,
  ...props
}: {
  text: string;
  subtext?: string;
  className?: string;
  as?: React.ElementType;
  contentClassName?: string;
} & React.HTMLAttributes<HTMLElement>) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Component
          title={text}
          className={cn(
            "block w-fit max-w-full truncate border-b border-dashed border-muted-foreground/40 text-left",
            className,
          )}
          {...props}
        >
          {text}
        </Component>
      </TooltipTrigger>
      <TooltipContent className={cn("max-w-xs whitespace-normal text-left", contentClassName)}>
        <p>{text}</p>
        {subtext && <p className="mt-1 font-mono text-[10px] opacity-80">{subtext}</p>}
      </TooltipContent>
    </Tooltip>
  );
}
