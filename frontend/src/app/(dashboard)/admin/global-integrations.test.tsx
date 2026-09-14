import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { GlobalIntegrations } from "./global-integrations";
import type { PlatformConfigView } from "@/lib/api";

/**
 * The point of these tests is a single rule: a failed, skipped or unknown read
 * on this page must never render as "not configured". This is a secrets
 * surface -- an admin who believes an integration is unset will re-enter a
 * credential that is already stored, and will misdiagnose an API outage as a
 * configuration problem.
 */
const { getConfig, workspaces, getGithubToken, updateConfig, deleteGithubToken } = vi.hoisted(() => ({
  getConfig: vi.fn(),
  workspaces: vi.fn(),
  getGithubToken: vi.fn(),
  updateConfig: vi.fn(),
  deleteGithubToken: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: {
    getConfig,
    workspaces,
    getGithubToken,
    saveGithubToken: vi.fn(),
    testGithubToken: vi.fn(),
    deleteGithubToken,
    updateConfig,
    testSlack: vi.fn(),
    testJira: vi.fn(),
    testSiem: vi.fn(),
    reseedEncryptionKey: vi.fn(),
  },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

// The GitHub App card does its own fetching and is covered by its own tests.
vi.mock("@/components/features/integrations", () => ({
  ConnectGithubCard: () => <div data-testid="connect-github-card" />,
}));

function config(over: Partial<PlatformConfigView> = {}): PlatformConfigView {
  return {
    anthropic_api_key_set: true,
    ai_provider: "anthropic",
    openai_compatible_base_url: "",
    openai_compatible_api_key_set: false,
    openai_compatible_model: "",
    slack_webhook_url_set: true,
    jira_url: "https://acme.atlassian.net",
    jira_api_token_set: true,
    jira_project_key: "SEC",
    jira_issue_type: "Task",
    jira_auto_create_severity: "High",
    siem_webhook_url_set: true,
    siem_export_severity: "",
    encryption_key_healthy: true,
    ...over,
  };
}

beforeEach(() => {
  getConfig.mockReset();
  workspaces.mockReset();
  getGithubToken.mockReset();
  updateConfig.mockReset();
  deleteGithubToken.mockReset();
  workspaces.mockResolvedValue([{ id: 1, name: "default", organization_id: 1, enforcement_mode: null }]);
  getGithubToken.mockResolvedValue({ token_set: true, created_at: null, expires_at: null });
});

describe("GlobalIntegrations honesty of state", () => {
  it("renders a failure, not an empty unconfigured form, when the config read fails", async () => {
    getConfig.mockRejectedValue(new Error("backend unreachable"));
    render(<GlobalIntegrations />);

    // The error is the content. Crucially the Slack/Jira/SIEM cards do not
    // render at all, so nothing on screen claims those are unconfigured.
    expect(await screen.findByText(/Couldn't load integration settings/i)).toBeDefined();
    expect(screen.getByText(/backend unreachable/)).toBeDefined();
    expect(screen.queryByText("Slack")).toBeNull();
    expect(screen.queryByText("SIEM Export")).toBeNull();
    expect(screen.getByRole("button", { name: /try again/i })).toBeDefined();
  });

  it("shows the configured integrations once the config read succeeds", async () => {
    getConfig.mockResolvedValue(config());
    render(<GlobalIntegrations />);

    expect(await screen.findByText("Slack")).toBeDefined();
    // One "Configured" line per set integration (Slack, Jira, SIEM, AI).
    expect(screen.getAllByText(/^Configured/).length).toBeGreaterThan(1);
  });

  it("does not render an unreadable GitHub token as 'no token'", async () => {
    getConfig.mockResolvedValue(config());
    getGithubToken.mockRejectedValue(new Error("500 from /api/github-token"));
    render(<GlobalIntegrations />);

    expect(await screen.findByText(/may or\s+may not be set/i)).toBeDefined();
    // The "Configured" affirmative must not appear for a token nobody read,
    // and neither must a placeholder implying the field is empty.
    expect(screen.queryByPlaceholderText(/ghp_/)).toBeNull();
  });

  it("keeps a stored SIEM 'Disabled' threshold disabled instead of coercing it back to High", async () => {
    // "" is the stored value for "auto-export off". The old `|| "High"`
    // coalesced that falsy value, so the page displayed a threshold the
    // server was not holding.
    getConfig.mockResolvedValue(config({ siem_export_severity: "" }));
    render(<GlobalIntegrations />);

    const select = (await screen.findByLabelText("Auto-export threshold")) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe(""));
  });

  it("falls back to High only when the SIEM threshold was never configured", async () => {
    getConfig.mockResolvedValue(config({ siem_export_severity: null }));
    render(<GlobalIntegrations />);

    const select = (await screen.findByLabelText("Auto-export threshold")) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe("High"));
  });
});

describe("GlobalIntegrations destructive actions", () => {
  it("does not revoke the AI key on a single click", async () => {
    getConfig.mockResolvedValue(config());
    render(<GlobalIntegrations />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke key" }));

    // A confirmation stating the consequence, and no mutation yet. Scoped to
    // the dialog: the same sentence also appears in the card's helper text,
    // which is exactly the problem -- it was only ever stated there.
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/fall back to no-AI behavior/i)).toBeDefined();
    expect(updateConfig).not.toHaveBeenCalled();
  });

  it("does not remove the GitHub token on a single click", async () => {
    getConfig.mockResolvedValue(config());
    render(<GlobalIntegrations />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));

    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/can't be read back/i)).toBeDefined();
    expect(deleteGithubToken).not.toHaveBeenCalled();
  });
});

describe("GlobalIntegrations secret fields", () => {
  it("marks every service secret as not-a-login for password managers", async () => {
    getConfig.mockResolvedValue(config());
    render(<GlobalIntegrations />);

    await screen.findByText("Slack");
    const secretIds = ["github-token", "anthropic-api-key", "slack-webhook-url", "jira-api-token", "siem-webhook-url"];
    for (const id of secretIds) {
      const el = document.getElementById(id) as HTMLInputElement | null;
      expect(el, `#${id} should be rendered`).not.toBeNull();
      expect(el!.getAttribute("type")).toBe("password");
      expect(el!.getAttribute("autocomplete")).toBe("off");
      expect(el!.getAttribute("spellcheck")).toBe("false");
    }
  });
});
