import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { FindingRow } from "@/components/features/findings";
import type { Finding } from "@/lib/api";

// FindingRow calls useRouter for its triage navigation. Mocked locally rather
// than in the shared setup: only this file needs a router, and a global stub
// would quietly satisfy any future test that ought to assert on navigation.
const refresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: (...args: unknown[]) => refresh(...args), push: vi.fn() }),
}));

const triage = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, triage: (...args: unknown[]) => triage(...args) },
  };
});

beforeEach(() => {
  triage.mockReset();
  refresh.mockReset();
});

// The osv-malware compromise-scope block (#331) is written as several
// paragraphs separated by blank lines, and OSV advisory bodies arrive with
// their own hard wrapping. HTML collapses that whitespace by default, which
// rendered the whole thing as one run-on paragraph with the block's
// "--- Compromise scope ---" separator sitting inline mid-sentence.
const SCOPE_DESCRIPTION = [
  "This package contains a DPRK supply-chain loader.",
  "https://osv.dev/vulnerability/MAL-2025-00001",
  "--- Compromise scope ---",
  "MAL-2025-00001 flags only version 1.2.9 of fetch-page-assets.",
  "Maintainer blast radius: audit this publisher's other packages.",
].join("\n\n");

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    target_id: 1,
    tool: "osv-malware",
    rule_id: "MAL-2025-00001",
    title: "Malicious code in fetch-page-assets (npm)",
    description: SCOPE_DESCRIPTION,
    file_path: "fetch-page-assets@1.2.9",
    line_start: null,
    line_end: null,
    severity: "Critical",
    priority_score: 100,
    branch: "main",
    state: "Open",
    cve_id: null,
    epss_score: null,
    kev_listed: false,
    first_seen: "2026-08-26T00:00:00Z",
    last_seen: "2026-08-26T00:00:00Z",
    sla_days: null,
    sla_violated: false,
    // Required on Finding as of the category grouping added upstream; the
    // server derives it from `tool`, and osv-malware maps to OSS/SCA.
    category: "OSS/SCA",
    ...overrides,
  };
}

describe("FindingRow description", () => {
  it("preserves the line breaks a multi-paragraph description carries", () => {
    render(<FindingRow finding={makeFinding()} />);

    // The description lives in the detail dialog the title button opens.
    fireEvent.click(screen.getByTitle("View vulnerability details and suggested fix"));

    const description = screen.getByText(/Compromise scope/);
    // Plain className check: this project does not load jest-dom matchers.
    expect(description.className).toContain("whitespace-pre-wrap");
    // The separator must start its own line rather than run into the prose
    // before it; without pre-wrap the collapsed text reads as one paragraph.
    expect(description.textContent).toContain(
      "\n\n--- Compromise scope ---\n\n",
    );
  });

  it("renders nothing for a finding with no description", () => {
    render(<FindingRow finding={makeFinding({ description: "" })} />);

    fireEvent.click(screen.getByTitle("View vulnerability details and suggested fix"));

    expect(screen.queryByText(/Compromise scope/)).toBeNull();
  });
});

describe("FindingRow triage", () => {
  function openTriage() {
    render(<FindingRow finding={makeFinding()} />);
    // Two Triage triggers exist in the markup -- one `density-compact-only`,
    // one in the comfortable block -- and CSS decides which is visible (#172).
    // jsdom applies no stylesheet, so both are matchable here; either opens
    // the same panel.
    fireEvent.click(screen.getAllByRole("button", { name: "Triage" })[0]);
  }

  it("closes the panel and refreshes once the write lands", async () => {
    triage.mockResolvedValue({ ok: true });
    openTriage();

    fireEvent.change(screen.getByPlaceholderText("Reason"), {
      target: { value: "Vendored, not shipped" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(triage).toHaveBeenCalledWith(1, "Accepted Risk", "Vendored, not shipped");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("surfaces a failed triage rather than silently re-enabling the buttons", async () => {
    // Was `try { ... } finally { setSubmitting(false) }` with no `catch`.
    triage.mockRejectedValue(new Error("409 Conflict"));
    openTriage();

    fireEvent.change(screen.getByPlaceholderText("Reason"), {
      target: { value: "Vendored, not shipped" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    const alert = await waitFor(() => screen.getByRole("alert"));
    expect(alert.textContent).toContain("409 Conflict");

    // The panel stays open with the typed reason intact, so retrying does not
    // mean retyping it -- and the row is not refreshed, because nothing about
    // it changed.
    expect((screen.getByPlaceholderText("Reason") as HTMLInputElement).value).toBe(
      "Vendored, not shipped",
    );
    expect(refresh).not.toHaveBeenCalled();
  });

  it("drops the previous failure once a retry succeeds", async () => {
    triage.mockRejectedValueOnce(new Error("503 Service Unavailable"));
    openTriage();

    fireEvent.click(screen.getByRole("button", { name: "False Positive" }));
    await waitFor(() => expect(screen.getByRole("alert")).not.toBeNull());

    triage.mockResolvedValue({ ok: true });
    fireEvent.click(screen.getByRole("button", { name: "False Positive" }));

    // A stale banner sitting under a succeeded write is its own false claim.
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
