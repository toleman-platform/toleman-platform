import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { FindingRow } from "./finding-row";
import type { Finding } from "@/lib/api";

// FindingRow calls useRouter for its triage navigation. Mocked locally rather
// than in the shared setup: only this file needs a router, and a global stub
// would quietly satisfy any future test that ought to assert on navigation.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

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
    ...overrides,
  };
}

describe("FindingRow description", () => {
  it("preserves the line breaks a multi-paragraph description carries", () => {
    render(<FindingRow finding={makeFinding()} />);

    // The description lives behind the details toggle on the title button.
    fireEvent.click(screen.getByTitle("Show details"));

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

    fireEvent.click(screen.getByTitle("Show details"));

    expect(screen.queryByText(/Compromise scope/)).toBeNull();
  });
});
