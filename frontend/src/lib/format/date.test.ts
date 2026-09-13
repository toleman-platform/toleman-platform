import { afterEach, describe, expect, it } from "vitest";
import { formatSince, parseServerTimestamp, serverDate, timeAgo, timeUntil } from "./date";

/**
 * These tests force a non-UTC timezone rather than trusting the runner's.
 *
 * That is the whole point of the file. Every datetime column in this schema
 * is naive UTC (backend/app/core/time.py's `utcnow`), so the API sends
 * "2026-09-13T10:00:00" with no designator -- and under a UTC runner the
 * broken reading and the correct one are byte-for-byte identical. A test
 * that only ran in CI's timezone would pass just as happily against the bug
 * it was written for, which is the shape of test this repository keeps
 * finding and deleting.
 *
 * Node honours a runtime `process.env.TZ` change (verified on v26), so each
 * case that cares picks a zone and restores it afterwards. Asia/Kolkata is
 * east of UTC, where the bug aged things forward; America/New_York is west,
 * where it aged them *backwards* into "Just now" -- the worse of the two,
 * because a stale scan rendered as fresh.
 */
const ORIGINAL_TZ = process.env.TZ;

afterEach(() => {
  if (ORIGINAL_TZ === undefined) delete process.env.TZ;
  else process.env.TZ = ORIGINAL_TZ;
});

/** A bare naive-UTC timestamp, exactly the shape FastAPI serialises. */
function bareUtcIso(msAgo = 0): string {
  return new Date(Date.now() - msAgo).toISOString().replace("Z", "");
}

describe("parseServerTimestamp", () => {
  it("reads a bare timestamp as UTC, not as local time", () => {
    process.env.TZ = "Asia/Kolkata";
    const bare = "2026-09-13T10:00:00";
    expect(parseServerTimestamp(bare)).toBe(Date.UTC(2026, 8, 13, 10, 0, 0));
    // And concretely: the naive reading is 5h30m off in this zone.
    expect(parseServerTimestamp(bare) - new Date(bare).getTime()).toBe(330 * 60_000);
  });

  it("is identical to appending Z by hand, in any zone", () => {
    for (const tz of ["UTC", "Asia/Kolkata", "America/New_York", "Pacific/Auckland"]) {
      process.env.TZ = tz;
      const bare = "2026-03-04T07:08:09";
      expect(parseServerTimestamp(bare)).toBe(Date.parse(`${bare}Z`));
    }
  });

  it("leaves a value that already carries a designator alone", () => {
    process.env.TZ = "America/New_York";
    // Z, a positive offset and a negative one: appending Z to any of these
    // would produce an unparseable string, so this also pins that the
    // regex is checked before the append rather than after.
    expect(parseServerTimestamp("2026-09-13T10:00:00Z")).toBe(Date.UTC(2026, 8, 13, 10, 0, 0));
    expect(parseServerTimestamp("2026-09-13T15:30:00+05:30")).toBe(Date.UTC(2026, 8, 13, 10, 0, 0));
    expect(parseServerTimestamp("2026-09-13T06:00:00-04:00")).toBe(Date.UTC(2026, 8, 13, 10, 0, 0));
  });

  it("handles the offset spelling without a colon", () => {
    expect(parseServerTimestamp("2026-09-13T15:30:00+0530")).toBe(Date.UTC(2026, 8, 13, 10, 0, 0));
  });

  it("returns NaN for something that is not a timestamp", () => {
    expect(Number.isNaN(parseServerTimestamp("not-a-date"))).toBe(true);
  });

  it("anchors epoch zero, in any zone", () => {
    for (const tz of ["UTC", "Asia/Kolkata", "America/New_York"]) {
      process.env.TZ = tz;
      expect(parseServerTimestamp("1970-01-01T00:00:00")).toBe(0);
    }
  });
});

describe("timeAgo", () => {
  it("does not age a recent scan forward, east of UTC", () => {
    // The reported symptom (#443): at UTC+5:30 a scan that finished five
    // minutes ago read as "5h ago". Fails against the pre-fix
    // implementation, which parsed the bare string as local time.
    process.env.TZ = "Asia/Kolkata";
    expect(timeAgo(bareUtcIso(5 * 60_000))).toBe("5m ago");
  });

  it("does not report a stale scan as fresh, west of UTC", () => {
    // The more dangerous direction. West of UTC the naive reading put the
    // timestamp in the future, the age went negative, and a negative
    // diffMin satisfies `diffMin <= 1` -- so something hours old rendered
    // as "Just now" on a page whose job is telling you when a repository
    // was last checked.
    process.env.TZ = "America/New_York";
    expect(timeAgo(bareUtcIso(3 * 60 * 60_000))).toBe("3h ago");
    expect(timeAgo(bareUtcIso(5 * 60_000))).toBe("5m ago");
  });

  it("agrees with itself whether or not the value carries a Z", () => {
    process.env.TZ = "Pacific/Auckland";
    const bare = bareUtcIso(90 * 60_000);
    expect(timeAgo(bare)).toBe(timeAgo(`${bare}Z`));
  });

  it("keeps its existing contract for coarser buckets", () => {
    process.env.TZ = "Asia/Kolkata";
    expect(timeAgo(bareUtcIso(26 * 60 * 60_000))).toBe("Yesterday");
    expect(timeAgo(bareUtcIso(3 * 24 * 60 * 60_000))).toBe("3 days ago");
    expect(timeAgo(bareUtcIso(14 * 24 * 60 * 60_000))).toBe("2w ago");
  });

  it("returns the input unchanged when it is not a timestamp", () => {
    // Worth pinning explicitly: the fix appends "Z" before parsing, so a
    // non-timestamp becomes "not-a-dateZ" internally. The function must
    // still echo back what it was given, not the doctored string.
    expect(timeAgo("not-a-date")).toBe("not-a-date");
  });
});

describe("serverDate", () => {
  it("returns a Date at the same instant parseServerTimestamp reports", () => {
    process.env.TZ = "Asia/Kolkata";
    const bare = "2026-09-13T10:00:00";
    expect(serverDate(bare).getTime()).toBe(parseServerTimestamp(bare));
  });

  it("yields an Invalid Date for junk, so existing isNaN guards still work", () => {
    expect(Number.isNaN(serverDate("not-a-date").getTime())).toBe(true);
  });
});

describe("formatSince", () => {
  it("formats a bare timestamp against UTC, not local time", () => {
    // 2026-01-01T02:00:00Z is still 2025-12-31 in New York. Read as local
    // time it would be the 1st in both, so this pins the parse rather than
    // just the formatting.
    process.env.TZ = "America/New_York";
    expect(formatSince("2026-01-01T02:00:00")).toBe(
      `since ${new Date(Date.UTC(2026, 0, 1, 2)).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      })}`
    );
  });

  it("falls back to the raw string rather than rendering Invalid Date", () => {
    expect(formatSince("not-a-date")).toBe("not-a-date");
  });
});

describe("timeUntil", () => {
  it("reads a bare future timestamp as UTC", () => {
    process.env.TZ = "Asia/Kolkata";
    // Two hours plus a minute, not exactly two hours: timeUntil floors, so
    // the milliseconds that elapse between building this string and
    // asserting on it are enough to turn an exact 2h into "in 1h".
    const future = new Date(Date.now() + 2 * 60 * 60_000 + 60_000).toISOString().replace("Z", "");
    expect(timeUntil(future)).toBe("in 2h");
  });

  it("says now rather than a negative duration for a moment already passed", () => {
    expect(timeUntil(bareUtcIso(60_000))).toBe("now");
  });
});
