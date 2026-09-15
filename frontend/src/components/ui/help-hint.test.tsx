import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { HelpHint } from "./help-hint";
import { HELP_CONTENT } from "@/lib/help-content";

/**
 * These assert against the visible panel, not against an accessibility-only
 * copy of it. The previous implementation was a Radix tooltip, which renders
 * its content a second time inside a visually hidden node; every assertion
 * scoped to `getByRole("tooltip")` therefore matched that hidden copy, and
 * would have stayed green with the visible panel blank or removed entirely.
 */
const TOPIC = {
  title: "Findings",
  body: "Every open finding across your targets.",
  docsUrl: "https://geekshiv.github.io/toleman/documentation/findings/lifecycle-and-scoring",
};

function openHint() {
  fireEvent.click(screen.getByRole("button", { name: "About Findings" }));
}

describe("HelpHint", () => {
  it("is a named button that is closed until it is asked for", () => {
    render(<HelpHint topic={TOPIC} />);
    const trigger = screen.getByRole("button", { name: "About Findings" });
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText(TOPIC.body)).toBeNull();
  });

  it("opens on click, which is what a touch user has", () => {
    // The reason this component is not a tooltip: Radix's tooltip trigger
    // returns early on a touch pointer and suppresses the focus path while a
    // pointer is down, so on a phone the affordance never opens at all.
    render(<HelpHint topic={TOPIC} />);
    openHint();
    expect(screen.getByRole("button", { name: "About Findings" }).getAttribute("aria-expanded")).toBe("true");
    expect(screen.queryByText(TOPIC.body)).not.toBeNull();
  });

  it("puts the documentation link in the document as a real, reachable link", () => {
    render(<HelpHint topic={TOPIC} />);
    openHint();
    const links = screen.getAllByRole("link", { name: /Learn more/ });
    // Exactly one: a tooltip would have produced a second, hidden copy with
    // the same accessible name.
    expect(links.length).toBe(1);
    expect(links[0].getAttribute("href")).toBe(TOPIC.docsUrl);
    expect(links[0].getAttribute("rel")).toBe("noopener noreferrer");
    expect(links[0].getAttribute("target")).toBe("_blank");
  });

  it("renders no link at all for a feature with no published documentation", () => {
    render(<HelpHint topic={{ title: "Findings", body: TOPIC.body }} />);
    openHint();
    expect(screen.queryByText(TOPIC.body)).not.toBeNull();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("closes on Escape and gives focus back to the trigger", () => {
    render(<HelpHint topic={TOPIC} />);
    openHint();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByText(TOPIC.body)).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "About Findings" }));
  });
});

describe("help content registry", () => {
  // A whitelist of the exact URLs, not a host-prefix check. `${DOCS}/coming-soon`
  // starts with the right host and ships a 404, so a prefix check would let
  // one through -- and the file's own header promises it never points a reader
  // at a 404. These five were confirmed against the published sitemap; the
  // Guardrails page deliberately has no link, because no published page covers
  // its six tabs.
  const CONFIRMED: Record<string, string> = {
    targets: "https://geekshiv.github.io/toleman/documentation/github-integration/targets-and-groups",
    findings: "https://geekshiv.github.io/toleman/documentation/findings/lifecycle-and-scoring",
    "ai-security": "https://geekshiv.github.io/toleman/documentation/scanning/ai-security",
    sbom: "https://geekshiv.github.io/toleman/documentation/scanning/sbom",
    "api-discovery": "https://geekshiv.github.io/toleman/documentation/scanning/api-discovery-and-scanning",
  };

  it("links only to documentation pages that were confirmed to exist", () => {
    const actual = Object.fromEntries(
      Object.entries(HELP_CONTENT)
        .filter(([, topic]) => topic.docsUrl !== undefined)
        .map(([key, topic]) => [key, topic.docsUrl]),
    );
    expect(actual).toEqual(CONFIRMED);
  });

  it("gives every feature a title and a body", () => {
    for (const topic of Object.values(HELP_CONTENT)) {
      expect(topic.title.length).toBeGreaterThan(0);
      expect(topic.body.length).toBeGreaterThan(0);
    }
  });
});
