import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import MaliciousPackagesPage from "./page";
import type { Finding, Target } from "@/lib/api";

// A negative OSV result used to render as three zeros and a sentence --
// indistinguishable from a repository nobody had ever checked. These tests
// pin the evidence that replaces it: per-repository packages-checked count,
// last-checked time, and a link to the SBOM the check ran against, plus the
// "never checked" / "check failed" states staying visibly distinct from a
// verified clean result (frontend/AGENTS.md 1.4).
const { findings, targets } = vi.hoisted(() => ({
  findings: vi.fn(),
  targets: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: {
    findings,
    targets,
    importGithubSbom: vi.fn(),
    malwareCheck: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));

function target(over: Partial<Target> = {}): Target {
  return {
    id: 1,
    workspace_id: 1,
    name: "svc",
    repo_url: "https://github.com/acme/svc",
    default_branch: "main",
    label: "Internal",
    criticality_weight: 2,
    groups: [],
    pipeline_integrated: false,
    pipeline_pr_url: null,
    is_ai_repo: false,
    is_ai_repo_signals: "",
    is_ai_repo_override: null,
    is_ai_repo_effective: false,
    enforcement_mode: null,
    api_base_url: null,
    diff_scoped_pr_scans: false,
    dependency_sync_status: null,
    dependency_sync_error: null,
    dependency_sync_at: null,
    dependency_component_count: null,
    malware_last_checked_at: null,
    malware_last_check_status: null,
    malware_packages_checked: null,
    is_active: true,
    deactivated_at: null,
    deleted_at: null,
    ...over,
  } as Target;
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    target_id: 1,
    tool: "osv-malware",
    rule_id: "MAL-2025-00001",
    title: "Malicious code in evil-pkg",
    description: "",
    file_path: "evil-pkg@1.0.0",
    line_start: null,
    line_end: null,
    severity: "Critical",
    priority_score: 90,
    branch: "main",
    state: "Open",
    cve_id: null,
    epss_score: null,
    kev_listed: false,
    first_seen: "2026-09-14T10:00:00",
    last_seen: "2026-09-14T10:00:00",
    sla_days: null,
    sla_violated: false,
    category: "OSS/SCA",
    ...over,
  } as Finding;
}

describe("Malicious Packages page: per-repository check evidence", () => {
  it("reports a clean repo as compared against N packages at a real time, not a bare zero", async () => {
    findings.mockResolvedValue({ items: [] });
    targets.mockResolvedValue([
      target({
        id: 1,
        name: "billing-service",
        malware_last_checked_at: "2026-09-15T08:00:00",
        malware_last_check_status: "clean",
        malware_packages_checked: 717,
      }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText(/Compared 717 packages against OSV/)).not.toBeNull();
    expect(screen.getByText("Clean")).not.toBeNull();
  });

  it("distinguishes a repo that has never been checked from a verified-clean one", async () => {
    findings.mockResolvedValue({ items: [] });
    targets.mockResolvedValue([
      target({ id: 2, name: "new-service", malware_last_checked_at: null }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText("Never checked")).not.toBeNull();
    expect(screen.queryByText("Clean")).toBeNull();
    expect(screen.getByText(/Never checked against OSV/)).not.toBeNull();
  });

  it("shows currently-open findings for a target even if its last completed check found something since mitigated", async () => {
    // The check itself said "found" at check time, but the finding it
    // produced has since been triaged to Mitigated on the Findings page.
    // The coverage row must reflect current triage state, not the stale
    // check-time verdict, or a resolved issue would keep reading as open.
    findings.mockResolvedValue({
      items: [finding({ target_id: 3, state: "Mitigated" })],
    });
    targets.mockResolvedValue([
      target({
        id: 3,
        name: "resolved-repo",
        malware_last_checked_at: "2026-09-14T10:00:00",
        malware_last_check_status: "found",
        malware_packages_checked: 12,
      }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText("Clean")).not.toBeNull();
    expect(screen.queryByText(/open$/)).toBeNull();
  });

  it("shows an open count badge for a target with a currently-open malicious finding", async () => {
    findings.mockResolvedValue({
      items: [finding({ target_id: 4, state: "Open" })],
    });
    targets.mockResolvedValue([
      target({
        id: 4,
        name: "flagged-repo",
        malware_last_checked_at: "2026-09-14T10:00:00",
        malware_last_check_status: "found",
        malware_packages_checked: 8,
      }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText("1 open")).not.toBeNull();
  });

  it("links each repository's coverage row to the SBOM it was checked against", async () => {
    findings.mockResolvedValue({ items: [] });
    targets.mockResolvedValue([
      target({ id: 5, name: "linked-repo", malware_last_checked_at: "2026-09-14T10:00:00", malware_packages_checked: 3, malware_last_check_status: "clean" }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    const link = (await screen.findByText("View SBOM")).closest("a");
    expect(link).not.toBeNull();
    expect(link?.getAttribute("href")).toBe("/targets/5?tab=dependencies");
  });

  it("does not render the confident empty state when findings failed to load", async () => {
    findings.mockRejectedValue(new Error("network error"));
    targets.mockResolvedValue([target({ id: 6 })]);

    render(<MaliciousPackagesPage />);

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("network error");
    // The honest-unknown message, not the "clean" empty state.
    expect(screen.queryByText("No malicious packages detected")).toBeNull();
    expect(await screen.findByText("Detected packages unavailable")).not.toBeNull();
  });

  it("reports the packages-checked total as unknown when no repository has ever completed a check", async () => {
    findings.mockResolvedValue({ items: [] });
    targets.mockResolvedValue([target({ id: 7, malware_packages_checked: null })]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText("No repository has completed an OSV check yet")).not.toBeNull();
  });

  it("sums packages checked across repositories for the headline stat", async () => {
    findings.mockResolvedValue({ items: [] });
    targets.mockResolvedValue([
      target({ id: 8, name: "a", malware_packages_checked: 400, malware_last_checked_at: "2026-09-14T10:00:00", malware_last_check_status: "clean" }),
      target({ id: 9, name: "b", malware_packages_checked: 317, malware_last_checked_at: "2026-09-14T10:00:00", malware_last_check_status: "clean" }),
    ]);

    render(<MaliciousPackagesPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByText("717")).not.toBeNull();
    expect(screen.getByText(/across 2 of 2 repos checked/)).not.toBeNull();
  });
});
