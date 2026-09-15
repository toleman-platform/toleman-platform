import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import SettingsPage from "./page";

/**
 * Every write on this page reported success by silence: `try`/`finally` with
 * no `catch`, so a rejected request re-enabled the button, left (or cleared)
 * the form and said nothing at all. These tests exist to make the failed and
 * the successful renders impossible to confuse, so each failure case is
 * paired with the success it used to be indistinguishable from.
 */

const {
  me,
  updateMe,
  changePassword,
  notificationPreferences,
  setNotificationPreferences,
  targets,
  updateTarget,
  apiTokens,
  createApiToken,
  revokeApiToken,
} = vi.hoisted(() => ({
  me: vi.fn(),
  updateMe: vi.fn(),
  changePassword: vi.fn(),
  notificationPreferences: vi.fn(),
  setNotificationPreferences: vi.fn(),
  targets: vi.fn(),
  updateTarget: vi.fn(),
  apiTokens: vi.fn(),
  createApiToken: vi.fn(),
  revokeApiToken: vi.fn(),
}));

// Spread over the real module rather than replaced wholesale: this page pulls
// in the targets barrel, and every module in that graph that imports a value
// from here would otherwise have to be enumerated in the factory.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      me,
      updateMe,
      changePassword,
      notificationPreferences,
      setNotificationPreferences,
      targets,
      updateTarget,
      apiTokens,
      createApiToken,
      revokeApiToken,
    },
  };
});

// The Workspace tab reaches TargetPicker, whose barrel pulls in the targets
// list and filter bar; those read the URL through these hooks and have no App
// Router above them in a plain component render.
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/settings",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

const USER = { id: 1, email: "ada@acme.com", name: "Ada", role: "admin" };

afterEach(() => {
  me.mockReset();
  updateMe.mockReset();
  notificationPreferences.mockReset();
  setNotificationPreferences.mockReset();
  targets.mockReset();
  updateTarget.mockReset();
  apiTokens.mockReset();
});

/** Mounts the page and waits for the profile read, which owns the name field. */
async function renderSettings() {
  render(<SettingsPage />);
  await screen.findByText(USER.email);
}

function nameField() {
  return screen.getByLabelText("Display name") as HTMLInputElement;
}

describe("Settings, saving a display name", () => {
  it("says why the save was refused, and keeps what the user typed", async () => {
    me.mockResolvedValue(USER);
    updateMe.mockRejectedValue(new Error("That name is already taken"));

    await renderSettings();
    fireEvent.change(nameField(), { target: { value: "Ada Lovelace" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("That name is already taken");
    // The confirmation a successful save shows must not appear beside it.
    expect(screen.queryByText("Saved")).toBeNull();
    // The rejected value is the only copy of it; a cleared field would mean
    // retyping something the server never stored.
    expect(nameField().value).toBe("Ada Lovelace");
  });

  it("confirms a save that worked, with no error treatment", async () => {
    me.mockResolvedValue(USER);
    updateMe.mockResolvedValue({ ...USER, name: "Ada Lovelace" });

    await renderSettings();
    fireEvent.change(nameField(), { target: { value: "Ada Lovelace" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("Settings, reading notification preferences", () => {
  async function openNotifications() {
    await renderSettings();
    fireEvent.click(screen.getByRole("button", { name: "Notifications" }));
  }

  it("renders an error with a retry instead of a skeleton that never resolves", async () => {
    me.mockResolvedValue(USER);
    notificationPreferences.mockRejectedValueOnce(new Error("preferences service unavailable"));
    notificationPreferences.mockResolvedValue([]);

    await openNotifications();

    expect(await screen.findByText("Couldn't load your notification preferences")).toBeTruthy();
    expect(screen.getByText("preferences service unavailable")).toBeTruthy();
    // Every checkbox defaults to off, so offering Save here would let the
    // user write "all notifications disabled" from values nobody has seen.
    expect(screen.queryByRole("button", { name: "Save Preferences" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("button", { name: "Save Preferences" })).toBeTruthy();
    expect(screen.queryByText("Couldn't load your notification preferences")).toBeNull();
    expect(notificationPreferences).toHaveBeenCalledTimes(2);
  });

  it("shows the stored preferences, not an empty grid, once the read lands", async () => {
    me.mockResolvedValue(USER);
    notificationPreferences.mockResolvedValue([
      { channel: "slack", event_type: "critical_finding", enabled: true },
    ]);

    await openNotifications();

    const box = (await screen.findByLabelText("Slack for New Critical finding")) as HTMLInputElement;
    expect(box.checked).toBe(true);
    expect((screen.getByLabelText("Slack for A scan fails") as HTMLInputElement).checked).toBe(false);
  });
});

describe("Settings, saving notification preferences", () => {
  async function openLoadedNotifications() {
    me.mockResolvedValue(USER);
    notificationPreferences.mockResolvedValue([
      { channel: "slack", event_type: "critical_finding", enabled: true },
    ]);
    render(<SettingsPage />);
    await screen.findByText(USER.email);
    fireEvent.click(screen.getByRole("button", { name: "Notifications" }));
    await screen.findByLabelText("Slack for New Critical finding");
  }

  it("surfaces the failure and leaves the edit in place to retry", async () => {
    setNotificationPreferences.mockRejectedValue(new Error("write rejected upstream"));

    await openLoadedNotifications();
    fireEvent.click(screen.getByLabelText("Slack for New Critical finding"));
    fireEvent.click(screen.getByRole("button", { name: "Save Preferences" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("write rejected upstream");
    expect(screen.queryByText("Saved")).toBeNull();
    // The toggle the user flipped is still flipped: a form reset here would
    // silently hand the old preferences back as if they had been kept.
    expect((screen.getByLabelText("Slack for New Critical finding") as HTMLInputElement).checked).toBe(false);
  });

  it("confirms a save that worked, with no error treatment", async () => {
    setNotificationPreferences.mockResolvedValue([]);

    await openLoadedNotifications();
    fireEvent.click(screen.getByLabelText("Slack for New Critical finding"));
    fireEvent.click(screen.getByRole("button", { name: "Save Preferences" }));

    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(setNotificationPreferences).toHaveBeenCalledTimes(1);
  });
});

describe("Settings, saving a target's configuration", () => {
  const TARGET = {
    id: 7,
    name: "acme/api",
    repo_url: "https://github.com/acme/api",
    default_branch: "main",
    label: "Prod",
    criticality_weight: 3,
  };

  async function openWorkspace() {
    me.mockResolvedValue(USER);
    targets.mockResolvedValue([TARGET]);
    apiTokens.mockResolvedValue([]);
    render(<SettingsPage />);
    await screen.findByText(USER.email);
    fireEvent.click(screen.getByRole("button", { name: "Workspace" }));
    await screen.findByDisplayValue("main");
  }

  it("keeps the unsaved edits and says why, rather than reverting to the stored values", async () => {
    updateTarget.mockRejectedValue(new Error("branch 'release' does not exist"));

    await openWorkspace();
    fireEvent.change(screen.getByDisplayValue("main"), { target: { value: "release" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("branch 'release' does not exist");
    expect(screen.queryByText("Saved")).toBeNull();
    // Dropping the draft here would repaint the server's "main" under a
    // failed save, which is exactly what a successful save looks like.
    expect(screen.getByDisplayValue("release")).toBeTruthy();
  });

  it("confirms a save that worked, with no error treatment", async () => {
    updateTarget.mockResolvedValue({ ...TARGET, default_branch: "release" });

    await openWorkspace();
    fireEvent.change(screen.getByDisplayValue("main"), { target: { value: "release" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
