import { afterEach, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { renderToStaticMarkup } from "react-dom/server";
import { Timestamp, useAbsoluteTimestamp } from "./timestamp";

/**
 * These tests force a non-UTC timezone, the same way lib/format/date.test.ts
 * does and for the same reason: under a UTC runner the hydration-unsafe
 * rendering and the safe one are byte-for-byte identical, so a test that
 * only ran in CI's timezone would pass just as happily against the bug.
 *
 * `renderToStaticMarkup` is what makes the pre-hydration assertions real --
 * it exercises the server render path, where `useSyncExternalStore` is
 * given the server snapshot, rather than approximating it.
 */
const ORIGINAL_TZ = process.env.TZ;

afterEach(() => {
  if (ORIGINAL_TZ === undefined) delete process.env.TZ;
  else process.env.TZ = ORIGINAL_TZ;
});

/** A bare naive-UTC timestamp, exactly the shape FastAPI serialises. */
const BARE = "2026-09-13T10:00:00";
const ISO = "2026-09-13T10:00:00.000Z";
const UTC_LABEL = "2026-09-13 10:00:00 UTC";

/** A timestamp that is genuinely `msAgo` old, for the relative mode. */
function bareUtcIso(msAgo: number): string {
  return new Date(Date.now() - msAgo).toISOString().replace("Z", "");
}

describe("Timestamp", () => {
  it("renders identical markup on a server in any timezone", () => {
    // The property the component exists for. Against a bare
    // `toLocaleString()` these four differ, which is the mismatch the
    // browser then hydrates over.
    const markups = ["UTC", "Asia/Kolkata", "America/New_York", "Pacific/Auckland"].map((tz) => {
      process.env.TZ = tz;
      return renderToStaticMarkup(<Timestamp value={BARE} />);
    });
    expect(new Set(markups).size).toBe(1);
    expect(markups[0]).toContain(UTC_LABEL);
  });

  it("marks the instant up as <time> carrying the ISO value and an absolute title", () => {
    process.env.TZ = "Asia/Kolkata";
    const html = renderToStaticMarkup(<Timestamp value={BARE} />);
    expect(html).toContain(`datetime="${ISO}"`);
    expect(html).toContain(`title="${UTC_LABEL}"`);
    expect(html).toContain(`>${UTC_LABEL}<`);
    // 15:30 is 10:00 UTC read in Asia/Kolkata: the server must not have
    // reached for the host's timezone at all.
    expect(html).not.toContain("15:30");
  });

  it("upgrades to the viewer's own formatting once mounted", () => {
    process.env.TZ = "Asia/Kolkata";
    const serverHtml = renderToStaticMarkup(<Timestamp value={BARE} />);
    const { container } = render(<Timestamp value={BARE} />);

    const el = container.querySelector("time");
    expect(el).toBeTruthy();
    const mountedText = el!.textContent;

    expect(mountedText).toBe(new Date(ISO).toLocaleString());
    // Pin that the two states really are different strings; without this,
    // "upgrades" would be asserting nothing.
    expect(serverHtml).toContain(UTC_LABEL);
    expect(mountedText).not.toBe(UTC_LABEL);
    // The machine-readable instant survives the upgrade.
    expect(el!.getAttribute("datetime")).toBe(ISO);
  });

  it("keeps the exact absolute time in the title behind a relative label", () => {
    process.env.TZ = "America/New_York";
    const threeHoursAgo = bareUtcIso(3 * 60 * 60_000);
    const { container } = render(<Timestamp value={threeHoursAgo} mode="relative" />);

    const el = container.querySelector("time");
    expect(el).toBeTruthy();
    expect(el!.textContent).toBe("3h ago");

    const title = el!.getAttribute("title") ?? "";
    expect(title).toContain("UTC");
    expect(title).toContain(new Date(`${threeHoursAgo}Z`).toLocaleString());
  });

  it("shows the absolute value server-side where a relative label has no stable form", () => {
    process.env.TZ = "America/New_York";
    const html = renderToStaticMarkup(<Timestamp value={bareUtcIso(3 * 60 * 60_000)} mode="relative" />);
    // The server's "3h ago" and the browser's are two separate clock
    // readings, so the server renders no relative label at all.
    expect(html).not.toContain("ago");
    expect(html).toContain(" UTC<");
  });

  it("renders stable date-only and time-only forms", () => {
    process.env.TZ = "Asia/Kolkata";
    expect(renderToStaticMarkup(<Timestamp value={BARE} mode="date" />)).toContain(">2026-09-13 UTC<");
    expect(renderToStaticMarkup(<Timestamp value={BARE} mode="time" />)).toContain(">10:00:00 UTC<");
  });

  it("renders the viewer's date-only and time-only forms once mounted", () => {
    process.env.TZ = "Asia/Kolkata";
    const dateOnly = render(<Timestamp value={BARE} mode="date" />);
    expect(dateOnly.container.querySelector("time")!.textContent).toBe(
      new Date(ISO).toLocaleDateString()
    );

    // A second `render` gets its own container, so this reads that one's
    // <time>, not the date-only element above.
    const timeOnly = render(<Timestamp value={BARE} mode="time" />);
    expect(timeOnly.container.querySelector("time")!.textContent).toBe(
      new Date(ISO).toLocaleTimeString()
    );
  });

  it("renders the caller's wording for an absent timestamp rather than an epoch", () => {
    const { container } = render(<Timestamp value={null} fallback="never used" />);
    expect(container.textContent).toBe("never used");
    // No <time>: there is no instant, and an empty or epoch `datetime`
    // would assert one.
    expect(container.querySelector("time")).toBeNull();
    expect(container.textContent).not.toContain("1970");
  });

  it("falls back to an em dash when the caller gives no wording", () => {
    const { container } = render(<Timestamp value={undefined} />);
    expect(container.textContent).toBe("—");
    expect(container.querySelector("time")).toBeNull();
  });

  it("treats an empty string as absent", () => {
    const { container } = render(<Timestamp value="" fallback="never" />);
    expect(container.textContent).toBe("never");
    expect(container.querySelector("time")).toBeNull();
  });

  it("echoes a value it cannot parse instead of inventing a date", () => {
    const { container } = render(<Timestamp value="not-a-date" />);
    expect(container.textContent).toBe("not-a-date");
    expect(container.querySelector("time")).toBeNull();
  });
});

function TitleProbe({ value }: { value: string }) {
  const label = useAbsoluteTimestamp(value);
  return <span title={label}>age</span>;
}

describe("useAbsoluteTimestamp", () => {
  it("gives a title attribute the same server-stable then local treatment", () => {
    process.env.TZ = "Asia/Kolkata";
    expect(renderToStaticMarkup(<TitleProbe value={BARE} />)).toContain(`title="${UTC_LABEL}"`);

    const { container } = render(<TitleProbe value={BARE} />);
    const title = container.querySelector("span")!.getAttribute("title") ?? "";
    expect(title).toContain(UTC_LABEL);
    expect(title).toContain(new Date(ISO).toLocaleString());
  });

  it("echoes an unparseable value", () => {
    const { container } = render(<TitleProbe value="not-a-date" />);
    expect(container.querySelector("span")!.getAttribute("title")).toBe("not-a-date");
  });
});
