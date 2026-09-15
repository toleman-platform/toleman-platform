import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { PrStateBadge } from "@/components/features/pull-requests/pr-state-badge";
import type { PullRequestState } from "@/types/github";

/**
 * Renders one badge and snapshots what it produced into plain strings.
 *
 * Strings, not element references: React reuses DOM nodes, so a reference
 * held across a second render reads the new markup and any comparison
 * between the two agrees with itself.
 */
function snapshotBadge(state: PullRequestState) {
  const { container } = render(<PrStateBadge state={state} />);
  const badge = container.firstElementChild as HTMLElement;
  const icon = badge.querySelector("svg");
  return {
    text: (badge.textContent ?? "").trim(),
    className: badge.getAttribute("class") ?? "",
    iconMarkup: icon?.innerHTML ?? "",
    spinningElements: container.querySelectorAll('[class*="animate-spin"]').length,
  };
}

describe("PrStateBadge", () => {
  it("names each state in the pull request's own vocabulary", () => {
    // Hardcoded rather than read back out of the component's own label map,
    // which would agree with whatever the map happened to say.
    expect(snapshotBadge("open").text).toBe("Open");
    expect(snapshotBadge("merged").text).toBe("Merged");
    expect(snapshotBadge("closed").text).toBe("Closed");
  });

  it("gives the three states three distinguishable renderings", () => {
    const open = snapshotBadge("open");
    const merged = snapshotBadge("merged");
    const closed = snapshotBadge("closed");

    expect(new Set([open.text, merged.text, closed.text]).size).toBe(3);
    // Colour and icon as well as wording: open and closed are both neutral by
    // design, so the label is the only thing separating them if the icon is
    // not, and colour alone is no help to a colourblind reviewer.
    expect(new Set([open.className, merged.className, closed.className]).size).toBe(3);
    expect(new Set([open.iconMarkup, merged.iconMarkup, closed.iconMarkup]).size).toBe(3);
    expect(open.iconMarkup).not.toBe("");
  });

  it("never animates, because none of these states is work in progress", () => {
    // The defect this component exists to fix: "open" went through the
    // async-task vocabulary as "running", whose rendering is a spinning
    // Loader2, so an open pull request span forever.
    expect(snapshotBadge("open").spinningElements).toBe(0);
    expect(snapshotBadge("merged").spinningElements).toBe(0);
    expect(snapshotBadge("closed").spinningElements).toBe(0);
  });

  it("reads merged as a positive terminal state and closed as a muted one", () => {
    const merged = snapshotBadge("merged");
    const closed = snapshotBadge("closed");

    expect(merged.className).toContain("chart-5");
    expect(closed.className).toContain("text-muted-foreground");
    expect(closed.className).not.toContain("chart-5");
  });

  it("keeps open neutral rather than borrowing a scan verdict's colour", () => {
    const open = snapshotBadge("open");

    // An open PR is a steady state, not a pass, a failure or a block.
    // Assert the colour utilities, not the substring "destructive": the Badge
    // primitive's own base class list always carries
    // `aria-invalid:ring-destructive/20`, a focus-ring concern with nothing to
    // do with this state's colour, so a bare substring check fails for a badge
    // that is styled entirely correctly.
    expect(open.className).not.toContain("chart-5");
    expect(open.className).not.toContain("text-destructive");
    expect(open.className).not.toContain("bg-destructive");
  });

  it("says nothing it does not know about a state it cannot name", () => {
    // The API is typed here but not at runtime. A state this does not model
    // must not be rendered as one of the three it does (AGENTS.md #1.4).
    const unexpected = snapshotBadge("draft" as unknown as PullRequestState);

    expect(unexpected.text).toBe("Unknown");
    expect(unexpected.spinningElements).toBe(0);
  });
});
