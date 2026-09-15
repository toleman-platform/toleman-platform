import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ConnectGithubCard } from "./connect-github-card";

/**
 * #355 is a rendering-placement bug, so these are the tests that actually
 * cover it: the backend has always known PUBLIC_API_URL was a localhost
 * address, and the card rendered that knowledge where nobody could see it.
 *
 * The warning lived inside `status.apps.map(...)`, so it only appeared next
 * to Apps that already existed. A fresh install has none, which is the only
 * install this can happen on -- so the operator clicking Connect for the
 * first time got no warning at all, and GitHub's rejection page instead.
 */

const { githubAppStatus, githubAppManifestData, githubAppSync, updateWebhookSecret, deleteGithubApp } = vi.hoisted(
  () => ({
    githubAppStatus: vi.fn(),
    githubAppManifestData: vi.fn(),
    githubAppSync: vi.fn(),
    updateWebhookSecret: vi.fn(),
    deleteGithubApp: vi.fn(),
  }),
);

vi.mock("@/lib/api", () => ({
  api: { githubAppStatus, githubAppManifestData, githubAppSync, updateWebhookSecret, deleteGithubApp },
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

afterEach(() => {
  githubAppStatus.mockReset();
  githubAppManifestData.mockReset();
  githubAppSync.mockReset();
  updateWebhookSecret.mockReset();
});

type StatusOverrides = Partial<{
  apps: unknown[];
  webhook_reachable: boolean;
  public_api_url: string;
}>;

function statusPayload(over: StatusOverrides = {}) {
  return {
    apps: [],
    app_configured: false,
    app_slug: null,
    installed: false,
    account_login: null,
    webhook_secret_set: false,
    webhook_reachable: true,
    public_api_url: "https://api.toleman.example.com",
    ...over,
  };
}

function appEntry(over: Record<string, unknown> = {}) {
  return {
    id: 1,
    app_id: "1",
    app_slug: "toleman-devsecops-abc",
    html_url: "https://github.com/apps/toleman-devsecops-abc",
    manage_url: "https://github.com/settings/apps/toleman-devsecops-abc",
    webhook_secret_set: true,
    installations: [{ installation_id: 111, account_login: "acme", account_type: "Organization" }],
    ...over,
  };
}

const connectButton = () => screen.getByRole("button", { name: "Connect GitHub" }) as HTMLButtonElement;

describe("ConnectGithubCard, creating an App from an address GitHub cannot reach", () => {
  it("warns and disables Connect on a fresh install, where there are no Apps to hang the warning off", async () => {
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "http://localhost:8000" }),
    );

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/GitHub will reject a new App/)).toBeDefined();
    expect(connectButton().disabled).toBe(true);
  });

  it("names the offending value rather than sending the operator to look it up", async () => {
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "http://localhost:8000" }),
    );

    render(<ConnectGithubCard />);

    await screen.findByText(/GitHub will reject a new App/);
    expect(screen.getAllByText("http://localhost:8000").length).toBeGreaterThan(0);
  });

  it("renders the warning before the create action, not after it", async () => {
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "http://localhost:8000" }),
    );

    render(<ConnectGithubCard />);
    const warning = await screen.findByText(/GitHub will reject a new App/);

    // The placement *is* the bug, so assert document order rather than mere
    // presence: a warning that renders under the button it is about is the
    // same failure in a different position.
    const relation = warning.compareDocumentPosition(connectButton());
    expect(relation & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("says what to do about it, including the restart the new value needs", async () => {
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "http://localhost:8000" }),
    );

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/services to pick it up/)).toBeDefined();
    expect(screen.getByText("cloudflared tunnel --url http://localhost:8000")).toBeDefined();
    // The fact that costs the most time to discover the hard way.
    expect(screen.getByText(/no API to change an App/)).toBeDefined();
  });

  it("blocks a LAN address the same way, and does not describe it as localhost", async () => {
    // An on-prem deployment on the office LAN is an ordinary configuration
    // and exactly as unreachable from github.com. The copy has to cover it
    // without claiming the value is a localhost address, which it isn't.
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "http://192.168.1.50:8000" }),
    );

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/resolves only on this machine or inside this network/)).toBeDefined();
    expect(connectButton().disabled).toBe(true);
    // It has dots, so the dotless advisory cannot be what caught it.
    expect(screen.queryByText(/whose host has no dot/)).toBeNull();
  });

  it("says PUBLIC_API_URL is unset rather than claiming an empty value is a localhost address", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ webhook_reachable: false, public_api_url: "" }));

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/has no usable address in it/)).toBeDefined();
    // The wrong-value branch describes a host that exists somewhere; saying
    // that about an empty value would be a lie next to an empty <code>.
    expect(screen.queryByText(/resolves only on this machine or inside this network/)).toBeNull();
    expect(connectButton().disabled).toBe(true);
  });

  it("reads a protocol-relative value the same way the backend does", async () => {
    // "//localhost:8000" has a host, and _webhook_hostname reads it fine.
    // Before the protocol-relative branch, hostOf returned "" for it and the
    // card rendered the *unset* copy about a value whose host the backend had
    // just read -- the two parsers disagreeing, which is the one thing hostOf
    // exists to prevent.
    githubAppStatus.mockResolvedValue(
      statusPayload({ webhook_reachable: false, public_api_url: "//localhost:8000" }),
    );

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/resolves only on this machine or inside this network/)).toBeDefined();
    expect(screen.queryByText(/has no usable address in it/)).toBeNull();
    expect(connectButton().disabled).toBe(true);
  });

  it("leaves Connect enabled when the backend reports a reachable host", async () => {
    githubAppStatus.mockResolvedValue(statusPayload());

    render(<ConnectGithubCard />);

    await screen.findByRole("button", { name: "Connect GitHub" });
    expect(connectButton().disabled).toBe(false);
    expect(screen.queryByText(/GitHub will reject a new App/)).toBeNull();
  });
});

describe("ConnectGithubCard, the advisory tier", () => {
  it("warns about a dotless host without blocking, since Toleman cannot see the operator's DNS", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ public_api_url: "http://backend:8000" }));

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/whose host has no dot/)).toBeDefined();
    // Advisory, not a block: clicking anyway is the override the backend
    // predicate deliberately does not offer.
    expect(connectButton().disabled).toBe(false);
  });

  it("does not call a globally routable IPv6 address internal", async () => {
    // Parser drift: new URL() reports "[2606:4700::1111]" where Python
    // reports "2606:4700::1111", and neither form has a dot -- so a public
    // v6 address used to trip the dotless advisory and get told it resolves
    // only inside the operator's own network. The backend already ruled on
    // this literal by allowing it; the UI must not contradict that.
    githubAppStatus.mockResolvedValue(statusPayload({ public_api_url: "http://[2606:4700::1111]:8000" }));

    render(<ConnectGithubCard />);

    await screen.findByRole("button", { name: "Connect GitHub" });
    expect(screen.queryByText(/whose host has no dot/)).toBeNull();
    expect(connectButton().disabled).toBe(false);
  });

  it("still warns about a dotless host written with a trailing dot", async () => {
    // The other half of the same drift: the backend strips the trailing dot
    // of an FQDN, so "backend." and "backend" are one host there and must be
    // one host here too.
    githubAppStatus.mockResolvedValue(statusPayload({ public_api_url: "http://backend.:8000" }));

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/whose host has no dot/)).toBeDefined();
    expect(connectButton().disabled).toBe(false);
  });

  it("says nothing about an ordinary public host", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ public_api_url: "https://api.toleman.example.com" }));

    render(<ConnectGithubCard />);

    await screen.findByRole("button", { name: "Connect GitHub" });
    expect(screen.queryByText(/whose host has no dot/)).toBeNull();
  });
});

describe("ConnectGithubCard, an App whose webhook has gone dead", () => {
  // Created while PUBLIC_API_URL was public, then pointed back at localhost:
  // a tunnel died, or a .env was reverted. The App is real, its deliveries
  // are not, and this is the degraded mode that genuinely does exist.
  const deadWebhook = () =>
    statusPayload({
      apps: [appEntry({ webhook_secret_set: true })],
      webhook_reachable: false,
      public_api_url: "http://localhost:8000",
    });

  it("does not report real-time scanning as active", async () => {
    githubAppStatus.mockResolvedValue(deadWebhook());

    render(<ConnectGithubCard />);

    await screen.findByText(/cannot arrive/);
    // The old two-way check read the secret alone and rendered a green
    // "real-time PR scanning active" next to a webhook nothing can reach.
    expect(screen.queryByText(/real-time PR scanning active/)).toBeNull();
  });

  it("explains the consequence, including the required check that blocks every PR", async () => {
    githubAppStatus.mockResolvedValue(deadWebhook());

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/required status check that nothing triggers blocks every PR/)).toBeDefined();
    // Distinct from the pre-create banner: nothing is being rejected here,
    // the App already exists.
    expect(screen.getByText(/This App already exists/)).toBeDefined();
  });

  it("still reports scanning as active when the host is reachable", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry({ webhook_secret_set: true })] }));

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/real-time PR scanning active/)).toBeDefined();
    expect(screen.queryByText(/cannot arrive/)).toBeNull();
  });

  it("still flags a missing webhook secret when the host is fine", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry({ webhook_secret_set: false })] }));

    render(<ConnectGithubCard />);

    expect(await screen.findByText(/No webhook secret set/)).toBeDefined();
  });
});

// M24: syncResult used to be one `string | null` rendered through the same
// neutral paragraph regardless of whether the sync succeeded or failed, so a
// failed sync read exactly like a successful one at a glance. These assert
// the two are now visibly different things, not just different words.
describe("ConnectGithubCard, syncing repos", () => {
  it("reports a successful sync distinctly from how a failure would render", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry()] }));
    githubAppSync.mockResolvedValue({ created: 3 });

    render(<ConnectGithubCard />);

    fireEvent.click(await screen.findByRole("button", { name: "Sync Repos Now" }));

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("3 new repo(s) added as targets");
    // A failure banner carries "destructive" styling (see the next test);
    // a real defect here would be this test passing with that class present.
    expect(banner.className).not.toContain("destructive");
  });

  it("reports a failed sync as an alert, not the same muted line a success gets", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry()] }));
    githubAppSync.mockRejectedValue(new Error("GitHub API rate limited"));

    render(<ConnectGithubCard />);

    fireEvent.click(await screen.findByRole("button", { name: "Sync Repos Now" }));

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("GitHub API rate limited");
    expect(banner.className).toContain("destructive");
    // The success copy must never appear next to a failed attempt.
    expect(screen.queryByText(/new repo\(s\) added as targets/)).toBeNull();
  });
});

describe("ConnectGithubCard, when the status read fails", () => {
  it("offers a retry instead of a skeleton that never resolves", async () => {
    // The failure mode this replaced: `status` stayed null, so the card kept
    // rendering a skeleton next to a permanently disabled button and a
    // one-line error, with nothing to click.
    githubAppStatus.mockRejectedValueOnce(new Error("network unreachable"));
    githubAppStatus.mockResolvedValue(statusPayload());

    render(<ConnectGithubCard />);

    expect(await screen.findByText("Couldn't load GitHub App status")).toBeDefined();
    expect(screen.getByText("network unreachable")).toBeDefined();
    expect(screen.queryByRole("button", { name: "Connect GitHub" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("button", { name: "Connect GitHub" })).toBeDefined();
    expect(githubAppStatus).toHaveBeenCalledTimes(2);
  });
});

// The webhook secret save was the last `try`/`finally` with no `catch` on this
// card, and the most costly one: it cleared the field and re-enabled the
// button whether or not the secret was stored, so a refused save looked
// exactly like an accepted one while GitHub's deliveries went on being
// rejected and PRs quietly stopped being scanned.
describe("ConnectGithubCard, saving a webhook secret", () => {
  const secretField = () =>
    screen.getByLabelText("Webhook secret for toleman-devsecops-abc") as HTMLInputElement;

  it("keeps the typed secret and says why, when the save is refused", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry({ webhook_secret_set: false })] }));
    updateWebhookSecret.mockRejectedValue(new Error("secret must be at least 16 characters"));

    render(<ConnectGithubCard />);

    await screen.findByLabelText("Webhook secret for toleman-devsecops-abc");
    fireEvent.change(secretField(), { target: { value: "too-short" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("secret must be at least 16 characters");
    expect(banner.className).toContain("destructive");
    // Pre-existing behaviour, pinned rather than introduced: the clear sits
    // after the await, so a rejected PUT never reached it. The field is the
    // only copy of what was typed, so a guard is worth having.
    expect(secretField().value).toBe("too-short");
    // And nothing on the card may claim the App is now verified.
    expect(screen.queryByText(/real-time PR scanning active/)).toBeNull();
    expect(screen.getByText(/No webhook secret set/)).toBeTruthy();
  });

  it("clears the field and re-reads the App's own state once the save returns", async () => {
    githubAppStatus.mockResolvedValueOnce(statusPayload({ apps: [appEntry({ webhook_secret_set: false })] }));
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry({ webhook_secret_set: true })] }));
    updateWebhookSecret.mockResolvedValue({ webhook_secret_set: true });

    render(<ConnectGithubCard />);

    await screen.findByLabelText("Webhook secret for toleman-devsecops-abc");
    fireEvent.change(secretField(), { target: { value: "a-properly-long-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    // Success is the backend saying the secret is set, re-read after the
    // write, rather than this component asserting it locally.
    expect(await screen.findByText(/real-time PR scanning active/)).toBeTruthy();
    expect(secretField().value).toBe("");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(updateWebhookSecret).toHaveBeenCalledWith("a-properly-long-secret", 1);
  });

  it("does not send an empty secret", async () => {
    githubAppStatus.mockResolvedValue(statusPayload({ apps: [appEntry({ webhook_secret_set: false })] }));

    render(<ConnectGithubCard />);

    await screen.findByLabelText("Webhook secret for toleman-devsecops-abc");
    expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
    expect(updateWebhookSecret).not.toHaveBeenCalled();
  });
});
