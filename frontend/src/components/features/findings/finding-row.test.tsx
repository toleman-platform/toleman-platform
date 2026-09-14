import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { FindingRow } from "./finding-row";
import type { Finding } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

// FindingDetailDialog (not exported -- it's driven here the way a real page
// does, by clicking a row's title) fetches three panels' worth of data on
// open. None of it matters to the focus/Escape behaviour under test, so each
// resolves to the smallest shape that renders without an error panel; tests
// below await that resolution before finishing so no pending `.then` leaks
// an unwrapped state update into whichever test runs next.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      findingScoreBreakdown: vi.fn().mockResolvedValue({
        finding_id: 1,
        stored_score: 320,
        score: 320,
        stale: false,
        base_points: 100,
        max_score: 1000,
        capped: false,
        signals: [],
      }),
      findingEnrichment: vi.fn().mockResolvedValue({
        finding_id: 1,
        cve_id: null,
        cve_description: null,
        cvss_score: null,
        cvss_vector: null,
        cwe_ids: null,
        references: null,
        fix_versions: null,
        fetched_at: null,
      }),
      suggestFix: vi.fn().mockResolvedValue({
        recommendation: "Upgrade the dependency.",
        strategy: "deterministic_sca",
        diff: null,
        file_path: null,
        new_content: null,
        ref: null,
        explanation: null,
      }),
    },
  };
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    target_id: 1,
    tool: "trivy",
    rule_id: "CVE-2024-1234",
    title: "Prototype pollution in lodash",
    description: "A crafted payload can pollute Object.prototype.",
    file_path: "package-lock.json",
    line_start: null,
    line_end: null,
    severity: "High",
    priority_score: 320,
    branch: "main",
    state: "Open",
    cve_id: "CVE-2024-1234",
    epss_score: null,
    kev_listed: false,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    sla_days: null,
    sla_violated: false,
    category: "OSS",
    ...overrides,
  };
}

// Opens the dialog the way a user does (clicking the row's title, not
// reaching into the unexported FindingDetailDialog), then waits for its
// async panels to settle so every test starts and ends between renders
// instead of mid-fetch.
async function openDetailDialog(finding: Finding = makeFinding()) {
  render(<FindingRow finding={finding} />);
  const trigger = screen.getByTitle("View vulnerability details and suggested fix");
  fireEvent.click(trigger);
  await waitFor(() => expect(screen.getByText(/Upgrade the dependency/)).not.toBeNull());
  return trigger;
}

describe("FindingDetailDialog", () => {
  it("opens on clicking the title and focuses its own close button", async () => {
    await openDetailDialog();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
  });

  it("closes and restores focus to the trigger on Escape", async () => {
    const trigger = await openDetailDialog();
    expect(screen.getByRole("dialog")).not.toBeNull();

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  // core M3: same defect class as ConfirmDialog -- an uncoordinated
  // `document` Escape listener that also reached whatever else was
  // listening for Escape (e.g. a `window`-level bulk-selection shortcut).
  it("does not let Escape reach a window listener behind it", async () => {
    const windowListener = vi.fn();
    window.addEventListener("keydown", windowListener);
    await openDetailDialog();
    fireEvent.keyDown(document, { key: "Escape" });
    window.removeEventListener("keydown", windowListener);

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(windowListener).not.toHaveBeenCalled();
  });

  it("traps Tab focus inside the dialog", async () => {
    await openDetailDialog();
    const closeBtn = screen.getByRole("button", { name: "Close" });

    // By the time the panels above have settled, the suggested-fix
    // "regenerate" button is the dialog's other focusable control (no diff
    // to raise a PR from in this mock, so it's the last one) -- Shift+Tab
    // from Close, the first, must wrap to it rather than leaving the dialog.
    const regenerate = screen.getByText("regenerate");
    expect(document.activeElement).toBe(closeBtn);

    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(regenerate);

    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(closeBtn);
  });
});

describe("FirstSeenAge (via FindingRow, showScore=false)", () => {
  it("renders a real day count for a well-formed first_seen", () => {
    const now = Date.parse("2026-03-10T00:00:00Z");
    vi.spyOn(Date, "now").mockReturnValue(now);
    render(<FindingRow finding={makeFinding({ first_seen: "2026-03-08T00:00:00Z" })} showScore={false} />);
    expect(screen.getByText("2d")).not.toBeNull();
    vi.restoreAllMocks();
  });

  // The defect: Math.max(0, Math.floor((now - NaN) / DAY)) is NaN, which
  // React renders as the literal string "NaNd" -- a nonsense age presented
  // with the same font-bold confidence as a real one. daysSince
  // (finding-group-row.tsx) already guards this identical computation with
  // `if (Number.isNaN(then)) return 0`; this is that same guard applied to
  // FirstSeenAge, so an unparseable timestamp reads as 0d instead of NaNd.
  it("falls back to 0d rather than NaNd for an unparseable first_seen", () => {
    render(<FindingRow finding={makeFinding({ first_seen: "not a date" })} showScore={false} />);
    expect(screen.getByText("0d")).not.toBeNull();
    expect(screen.queryByText(/NaN/)).toBeNull();
  });
});
