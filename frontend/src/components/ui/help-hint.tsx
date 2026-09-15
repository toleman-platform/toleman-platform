"use client";

import * as React from "react";
import { ExternalLink, HelpCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { HelpTopic } from "@/lib/help-content";
import { cn, safeHref } from "@/lib/utils";

export interface HelpHintProps {
  /** What the hint explains. Shared copy lives in `@/lib/help-content`. */
  topic: HelpTopic;
  /** Side of the trigger the hint opens on. */
  side?: React.ComponentProps<typeof TooltipContent>["side"];
  className?: string;
}

/**
 * A small "?" next to a heading that says, in plain language, what the feature
 * does and who it is for, plus a link to the documentation page when one is
 * published.
 *
 * The trigger is a real button with an accessible name ("About Targets"), so
 * it is reachable by keyboard and announced as an affordance; Radix opens the
 * hint on focus as well as hover and wires the content up as the trigger's
 * description.
 */
export function HelpHint({ topic, side = "bottom", className }: HelpHintProps) {
  const { title, body, docsUrl } = topic;
  const docsHref = safeHref(docsUrl);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label={`About ${title}`}
          className={cn(
            "size-6 rounded-full text-muted-foreground hover:text-foreground",
            className,
          )}
        >
          {/* Sized explicitly so Button's default 16px svg rule does not
              apply; 14px keeps the affordance quieter than the heading. */}
          <HelpCircle className="size-3.5" aria-hidden="true" />
        </Button>
      </TooltipTrigger>
      <TooltipContent
        side={side}
        className="max-w-xs whitespace-normal text-left"
      >
        {/* Spans, not paragraphs: Radix renders this content a second time
            inside a visually hidden <span> for screen readers, and block-level
            elements are not valid there. */}
        <span className="block font-medium">{title}</span>
        <span className="mt-1 block text-background/90">{body}</span>
        {docsHref && (
          <a
            href={docsHref}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`Learn more about ${title}`}
            className="mt-2 inline-flex items-center gap-1 underline underline-offset-2"
          >
            Learn more
            <ExternalLink className="size-3" aria-hidden="true" />
          </a>
        )}
      </TooltipContent>
    </Tooltip>
  );
}
