import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { HelpHint } from "./help-hint";
import { HELP_CONTENT } from "@/lib/help-content";

// Radix's popper measures its arrow with a ResizeObserver, which jsdom does
// not implement. Without this the hint throws the moment it opens, so the
// stub is what makes the "content renders" assertions possible at all; it
// never needs to report a size, because nothing here asserts on position.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

/** Focusing the trigger is how a keyboard user opens the hint. */
async function openHint(name: string) {
  fireEvent.focus(screen.getByRole("button", { name }));
  return screen.findByRole("tooltip");
}

describe("HelpHint", () => {
  it("names the feature it explains, for screen readers", () => {
    render(<HelpHint topic={HELP_CONTENT.targets} />);

    // A bare "?" glyph would announce as nothing useful; the name has to say
    // which feature this hint is about.
    const trigger = screen.getByRole("button", { name: "About Targets" });

    // And it has to be a real button, so it lands in the tab order without a
    // tabindex of its own.
    expect(trigger.tagName).toBe("BUTTON");
  });

  it("shows the explanation and a documentation link when opened", async () => {
    const sbom = HELP_CONTENT.sbom;
    render(<HelpHint topic={sbom} />);

    const hint = await openHint(`About ${sbom.title}`);

    expect(hint.textContent).toContain(sbom.title);
    expect(hint.textContent).toContain(sbom.body);

    const link = within(hint).getByRole("link", { name: /learn more/i });
    expect(link.getAttribute("href")).toBe(sbom.docsUrl);
    expect(link.getAttribute("target")).toBe("_blank");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("omits the link when the feature has no published documentation page", async () => {
    render(
      <HelpHint
        topic={{
          title: "Scan queue",
          body: "Scans waiting to run, and what is running now.",
        }}
      />,
    );

    const hint = await openHint("About Scan queue");

    // The explanation still shows; only the link is gone. Linking a feature
    // with no published page would send the reader to a 404.
    expect(hint.textContent).toContain(
      "Scans waiting to run, and what is running now.",
    );
    expect(within(hint).queryByRole("link")).toBeNull();
  });

  it("gives every wired feature a real explanation", () => {
    // The registry is the single source of this copy, so an entry added with
    // an empty body (or a placeholder docs URL) fails here rather than
    // shipping as an empty hint.
    for (const [key, topic] of Object.entries(HELP_CONTENT)) {
      expect(topic.title.length, key).toBeGreaterThan(0);
      expect(topic.body.length, key).toBeGreaterThan(20);
      if (topic.docsUrl !== undefined) {
        expect(
          topic.docsUrl.startsWith("https://geekshiv.github.io/toleman/"),
          key,
        ).toBe(true);
      }
    }
  });
});
