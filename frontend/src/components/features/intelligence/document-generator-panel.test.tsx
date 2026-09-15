import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { WhatsIncludedCard } from "./document-generator-panel";

/**
 * The point of these is the *closed* state. This card used to render its
 * whole list unconditionally on API Discovery, SBOM and Reports, so a test
 * that only checked "the items are on screen" would have passed against the
 * old component too and proved nothing.
 *
 * Every assertion re-queries the DOM rather than holding a node across a
 * re-render: React reuses the same button element when the card opens, so a
 * reference captured before the click reads the state after it.
 */
const ITEMS = [
  "Every route found in the source, with the file and line it came from",
  "Routes grouped by HTTP method",
  "Endpoints that appeared since the last run, flagged as new",
];
const FOOTNOTE = "All figures reflect each target's default branch.";

// A regex, not an exact string: the trigger also holds a decorative chevron,
// and the accessible-name algorithm's spacing around a hidden child is not
// worth asserting on.
function trigger() {
  return screen.getByRole("button", { name: /What's included/ });
}

function panel() {
  const id = trigger().getAttribute("aria-controls");
  return id === null ? null : document.getElementById(id);
}

describe("WhatsIncludedCard", () => {
  it("keeps the list out of the page until the reader asks for it", () => {
    render(<WhatsIncludedCard items={ITEMS} footnote={FOOTNOTE} />);

    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(trigger().getAttribute("aria-controls")).toBeNull();
    for (const item of ITEMS) {
      expect(screen.queryByText(item)).toBeNull();
    }
    expect(screen.queryByText(FOOTNOTE)).toBeNull();
    // Nothing is merely hidden with CSS: the copy is not in the document at
    // all, so it is not in the accessibility tree either.
    expect(document.querySelector("li")).toBeNull();
  });

  it("reveals every item and the footnote on click", () => {
    render(<WhatsIncludedCard items={ITEMS} footnote={FOOTNOTE} />);
    fireEvent.click(trigger());

    expect(trigger().getAttribute("aria-expanded")).toBe("true");
    for (const item of ITEMS) {
      expect(screen.queryByText(item)).not.toBeNull();
    }
    expect(screen.queryByText(FOOTNOTE)).not.toBeNull();
    // Items in, same number of items out. ITEMS is this file's own fixture,
    // not anything the component computes, so this cannot agree with the
    // implementation by construction.
    expect(document.querySelectorAll("li").length).toBe(ITEMS.length);
  });

  it("closes again on a second click", () => {
    render(<WhatsIncludedCard items={ITEMS} footnote={FOOTNOTE} />);
    fireEvent.click(trigger());
    const openedText = screen.getByText(ITEMS[0]).textContent;
    fireEvent.click(trigger());

    expect(openedText).toBe(ITEMS[0]);
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText(ITEMS[0])).toBeNull();
    expect(screen.queryByText(FOOTNOTE)).toBeNull();
  });

  it("points aria-controls at the region that actually holds the items", () => {
    render(<WhatsIncludedCard items={ITEMS} footnote={FOOTNOTE} />);
    fireEvent.click(trigger());

    const region = panel();
    expect(region).not.toBeNull();
    expect(region?.textContent).toContain(ITEMS[1]);
    expect(region?.textContent).toContain(FOOTNOTE);
  });

  it("stays a heading-navigation stop while closed", () => {
    render(<WhatsIncludedCard items={ITEMS} />);

    const heading = screen.getByRole("heading", { name: /What's included/ });
    expect(heading.tagName).toBe("H2");
    expect(heading.querySelector("button")).not.toBeNull();
  });

  it("renders no footnote paragraph when the caller gives none", () => {
    render(<WhatsIncludedCard items={ITEMS} />);
    fireEvent.click(trigger());

    const region = panel();
    expect(region).not.toBeNull();
    expect(region?.querySelectorAll("p").length).toBe(0);
    expect(region?.textContent).toContain(ITEMS[0]);
  });

  it("opens even when the caller has nothing to list yet", () => {
    // Reports passes a single 'nothing chosen yet' line rather than an empty
    // array; the disclosure must still be openable so that line is reachable.
    render(<WhatsIncludedCard items={["Nothing yet, choose at least one section above."]} />);
    fireEvent.click(trigger());

    expect(trigger().getAttribute("aria-expanded")).toBe("true");
    expect(screen.queryByText("Nothing yet, choose at least one section above.")).not.toBeNull();
  });
});
