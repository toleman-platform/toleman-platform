import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  ScanHealthBadge,
  ScanHealthNotice,
  ScanProgress,
  ScanStatusBadge,
  formatDuration,
  scanProgressLabel,
} from "@/components/features/scans/scan-status";

describe("formatDuration", () => {
  it("shows seconds under a minute", () => {
    expect(formatDuration(45)).toBe("45s");
  });

  it("shows minutes and seconds", () => {
    expect(formatDuration(130)).toBe("2m 10s");
  });

  it("drops the seconds on a whole minute", () => {
    expect(formatDuration(120)).toBe("2m");
  });

  it("drops seconds entirely past an hour, where they are noise", () => {
    expect(formatDuration(3780)).toBe("1h 3m");
    expect(formatDuration(7200)).toBe("2h");
  });

  it("never renders a negative duration", () => {
    expect(formatDuration(-5)).toBe("0s");
  });
});

describe("scanProgressLabel", () => {
  it("counts down when an estimate exists", () => {
    expect(scanProgressLabel(10, 40)).toBe("about 30s left");
  });

  it("falls back to elapsed time when there is no estimate", () => {
    // The core rule of #212: with too little history the UI states what it
    // knows (how long this has been running) rather than inventing a
    // number it cannot support.
    expect(scanProgressLabel(45, null)).toBe("running for 45s");
  });

  it("stops predicting once the estimate is overshot", () => {
    // Counting into the negative, or freezing at "0s left" while the scan
    // keeps going, both insist on an estimate that has already been proven
    // wrong.
    expect(scanProgressLabel(90, 60)).toBe("running for 1m 30s · longer than usual");
  });

  it("treats hitting the estimate exactly as overshooting", () => {
    expect(scanProgressLabel(60, 60)).toContain("longer than usual");
  });
});

describe("ScanStatusBadge", () => {
  it("distinguishes queued from running", () => {
    // Queued is the gap between the API accepting a dispatch and a worker
    // picking it up. Collapsing it into "running" would claim work had
    // started that may not have.
    const { rerender } = render(<ScanStatusBadge phase="queued" />);
    expect(screen.getByText("Queued")).toBeTruthy();

    rerender(<ScanStatusBadge phase="running" />);
    expect(screen.getByText("Running")).toBeTruthy();
  });

  it("attributes the phase to a tool when given one", () => {
    render(<ScanStatusBadge phase="running" tool="semgrep" />);
    expect(screen.getByText("Running · semgrep")).toBeTruthy();
  });

  it("renders completed and failed distinctly", () => {
    const { rerender } = render(<ScanStatusBadge phase="completed" />);
    expect(screen.getByText("Completed")).toBeTruthy();
    rerender(<ScanStatusBadge phase="failed" />);
    expect(screen.getByText("Failed")).toBeTruthy();
  });
});

describe("ScanProgress", () => {
  it("announces progress politely to assistive tech", () => {
    render(<ScanProgress phase="running" elapsedSeconds={10} etaSeconds={40} />);
    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(status.textContent).toBe("about 30s left");
  });

  it("keeps the live region mounted when there is nothing to say", () => {
    // A live region inserted at the same moment as its first message can
    // miss that message entirely, so the region is always present.
    render(<ScanProgress phase="completed" />);
    expect(screen.getByRole("status")).toBeTruthy();
  });

  it("surfaces the failure reason rather than a bare 'Failed'", () => {
    // A clone timeout and a missing tool need different responses from the
    // user; "Failed" alone distinguishes neither.
    render(<ScanProgress phase="failed" error="Timed out: no update received within 30 minutes" />);
    expect(screen.getByRole("status").textContent).toContain("Timed out");
  });

  it("shows elapsed time when the server gave no estimate", () => {
    render(<ScanProgress phase="running" elapsedSeconds={45} etaSeconds={null} />);
    expect(screen.getByRole("status").textContent).toBe("running for 45s");
  });
});

describe("ScanHealthBadge (#229)", () => {
  it("marks a run the platform refused to trust", () => {
    // A scan can complete, exit cleanly and report zero findings while
    // having read a half-written vulnerability database. "Completed · 0
    // findings" is then the most misleading thing the UI can say.
    render(<ScanHealthBadge health="suspect" />);
    expect(screen.getByText("Not authoritative")).toBeTruthy();
  });

  it("says nothing about a healthy run", () => {
    const { container } = render(<ScanHealthBadge health="healthy" />);
    expect(container.textContent).toBe("");
  });

  it("says nothing about an unassessed run", () => {
    // Every scan recorded before #229 is "unknown". Badging those would put
    // a warning on a year of legitimate history, and a warning on
    // everything is a warning on nothing; making no claim is the honest
    // position.
    const { container } = render(<ScanHealthBadge health="unknown" />);
    expect(container.textContent).toBe("");
  });
});

describe("ScanHealthNotice (#229)", () => {
  it("gives the reason, not just the verdict", () => {
    // "Not authoritative" alone tells a user something is wrong without
    // telling them what to do; a stale vulnerability DB and a tool that
    // resolved no manifests call for different responses.
    render(
      <ScanHealthNotice
        health="suspect"
        note="trivy ran without a vulnerability database, so it could not have found any CVE."
      />
    );
    expect(screen.getByText(/not treated as authoritative/i)).toBeTruthy();
    expect(screen.getByText(/without a vulnerability database/i)).toBeTruthy();
  });

  it("still renders the verdict when no reason was recorded", () => {
    render(<ScanHealthNotice health="suspect" note="" />);
    expect(screen.getByText(/not treated as authoritative/i)).toBeTruthy();
  });

  it("renders nothing for a healthy run", () => {
    const { container } = render(<ScanHealthNotice health="healthy" note="" />);
    expect(container.textContent).toBe("");
  });
});
