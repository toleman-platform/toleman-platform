import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { NewTargetForm } from "./new-target-form";

// Issue #356: the workspace was typed into a number input defaulting to a
// hardcoded `1`. On a fresh deployment that default is a lie, and submitting
// it pushed a dangling FK at POST /api/targets, whose unhandled
// IntegrityError reached the browser as a bogus CORS error. These tests pin
// the properties the fix rests on: the id is chosen from the real list rather
// than typed, an empty list is reported as what it actually means for the
// person reading it, and a failed load neither masquerades as "none exist"
// nor destroys the form.
//
// Only the api boundary and the router are mocked, so the picker and the
// AsyncContent state ladder under test are the real ones.
const { workspaces, createTarget, me } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  createTarget: vi.fn(),
  me: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { workspaces, createTarget, me },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

const ADMIN = { id: 1, email: "a@example.com", name: "A", role: "admin" };
const DEVELOPER = { id: 2, email: "d@example.com", name: "D", role: "developer" };

afterEach(() => {
  workspaces.mockReset();
  createTarget.mockReset();
  me.mockReset();
});

describe("NewTargetForm workspace picker", () => {
  it("sends the workspace the user picked, and offers no id field to type into", async () => {
    workspaces.mockResolvedValue([
      { id: 7, name: "prod" },
      { id: 9, name: "staging" },
    ]);
    me.mockResolvedValue(ADMIN);
    createTarget.mockResolvedValue({ id: 1 });
    render(<NewTargetForm />);

    const picker = await screen.findByLabelText("Workspace");
    // The regression itself: a free-text/number workspace id.
    expect(screen.queryByPlaceholderText("Workspace ID")).toBeNull();

    fireEvent.change(picker, { target: { value: "9" } });
    fireEvent.change(screen.getByPlaceholderText(/Target name/), { target: { value: "repo" } });
    fireEvent.change(screen.getByPlaceholderText(/Repo URL/), {
      target: { value: "https://github.com/acme/repo" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add Target" }));

    await waitFor(() => expect(createTarget).toHaveBeenCalledTimes(1));
    expect(createTarget.mock.calls[0][0]).toMatchObject({
      workspace_id: 9,
      name: "repo",
      repo_url: "https://github.com/acme/repo",
    });
  });

  it("defaults to the only workspace when there is exactly one", async () => {
    workspaces.mockResolvedValue([{ id: 4, name: "default" }]);
    me.mockResolvedValue(ADMIN);
    createTarget.mockResolvedValue({ id: 1 });
    render(<NewTargetForm />);

    await screen.findByLabelText("Workspace");
    fireEvent.change(screen.getByPlaceholderText(/Target name/), { target: { value: "repo" } });
    fireEvent.change(screen.getByPlaceholderText(/Repo URL/), {
      target: { value: "https://github.com/acme/repo" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add Target" }));

    // No interaction with the picker at all: the single workspace is already
    // the selection, so the common case stays a two-field form.
    await waitFor(() => expect(createTarget).toHaveBeenCalledTimes(1));
    expect(createTarget.mock.calls[0][0]).toMatchObject({ workspace_id: 4 });
  });
});

describe("NewTargetForm empty workspace list", () => {
  it("offers an admin the create flow, because for them empty means none exist", async () => {
    workspaces.mockResolvedValue([]);
    me.mockResolvedValue(ADMIN);
    render(<NewTargetForm />);

    const link = await screen.findByRole("link", { name: "Create a workspace" });
    // Plain attribute check: this project does not load jest-dom matchers.
    expect(link.getAttribute("href")).toBe("/workspaces");
    expect(screen.queryByRole("button", { name: "Add Target" })).toBeNull();
    expect(createTarget).not.toHaveBeenCalled();
  });

  it("does not send a non-admin to a page that will 403 them", async () => {
    // GET /api/workspaces is scoped by accessible_workspace_ids, so [] here
    // means "you are a member of none", not "none exist"; and
    // POST /api/workspaces is admin-only, so the create CTA would be a dead
    // end. Same confident-but-wrong empty state the picker itself avoids,
    // one level up.
    workspaces.mockResolvedValue([]);
    me.mockResolvedValue(DEVELOPER);
    render(<NewTargetForm />);

    await screen.findByText("No workspaces available to you");
    expect(screen.queryByRole("link", { name: "Create a workspace" })).toBeNull();
  });

  it("withholds the create CTA while the caller's role is still unknown", async () => {
    // An unknown role takes the non-admin branch on purpose: "ask an admin"
    // is merely unhelpful to an admin, a CTA that 403s is a dead end.
    workspaces.mockResolvedValue([]);
    me.mockRejectedValue(new Error("500"));
    render(<NewTargetForm />);

    await screen.findByText("No workspaces available to you");
    expect(screen.queryByRole("link", { name: "Create a workspace" })).toBeNull();
  });
});

describe("NewTargetForm failed workspace list", () => {
  it("says the list failed rather than claiming there are none", async () => {
    workspaces.mockRejectedValue(new Error("503"));
    me.mockResolvedValue(ADMIN);
    render(<NewTargetForm />);

    await screen.findByText("Couldn't load workspaces");
    expect(screen.getByText("503")).toBeTruthy();
    // The distinction that matters: not the empty state, which would send
    // the reader off to create a workspace they may well already have.
    expect(screen.queryByText("No workspaces yet")).toBeNull();
  });

  it("recovers from a transient failure without a page reload", async () => {
    // A single 503 used to replace the form with a dead-end message, with no
    // way back short of reloading the page. AsyncContent's retry is the point
    // of routing this through it rather than hand-rolling the ladder.
    workspaces.mockRejectedValueOnce(new Error("503")).mockResolvedValue([{ id: 3, name: "prod" }]);
    me.mockResolvedValue(ADMIN);
    render(<NewTargetForm />);

    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));

    const picker = await screen.findByLabelText("Workspace");
    expect((picker as HTMLSelectElement).value).toBe("3");
  });
});
