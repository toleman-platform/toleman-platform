import { describe, expect, it } from "vitest";
import { filenameFromContentDisposition } from "./api";

// (#302) Downloads take their filename from the server's Content-Disposition
// rather than rebuilding the naming rule client-side, because the server's
// name carries the "filtered" / "NofM-sections" markers that stop a narrowed
// export landing on disk under a full report's name. That only holds if the
// header is parsed correctly, including the RFC 5987 `filename*` the backend
// sends alongside the ASCII fallback (see app/core/downloads.py).

describe("filenameFromContentDisposition", () => {
  it("reads the plain quoted filename", () => {
    expect(filenameFromContentDisposition('attachment; filename="report.csv"')).toBe("report.csv");
  });

  it("prefers the UTF-8 filename* over the ASCII fallback", () => {
    const header =
      "attachment; filename=\"toleman-posture-report-repo.csv\"; " +
      "filename*=UTF-8''toleman-posture-report-%E6%97%A5%E6%9C%AC%E8%AA%9E.csv";
    expect(filenameFromContentDisposition(header)).toBe("toleman-posture-report-日本語.csv");
  });

  it("keeps the narrowing markers the server put in the name", () => {
    const header = 'attachment; filename="toleman-posture-report-repo-filtered-2of6-sections-20260913.csv"';
    const name = filenameFromContentDisposition(header);
    expect(name).toContain("filtered");
    expect(name).toContain("2of6-sections");
  });

  it("handles an unquoted filename", () => {
    expect(filenameFromContentDisposition("attachment; filename=report.pdf")).toBe("report.pdf");
  });

  it("returns empty string for a missing or unparseable header, so the caller can fall back", () => {
    expect(filenameFromContentDisposition(null)).toBe("");
    expect(filenameFromContentDisposition("attachment")).toBe("");
  });

  it("falls back to the ASCII name rather than throwing on a malformed escape", () => {
    // A truncated percent-escape makes decodeURIComponent throw; a download
    // must not fail over that.
    const header = "attachment; filename=\"safe.csv\"; filename*=UTF-8''bad%E0%A4name.csv";
    expect(filenameFromContentDisposition(header)).toBe("safe.csv");
  });
});
