import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { NewTargetForm } from "./new-target-form";

// Issue #356: the workspace was typed into a number input defaulting to a
// hardcoded `1`. On a fresh deployment with no workspaces that default was a
// lie, and submitting it pushed a dangling FK at POST /api/targets, whose
// unhandled IntegrityError reached the browser as a bogus CORS error. These
// tests pin the two properties that fix rests on: the id is chosen from the
// real list rather than typed, and "no workspaces exist" is a visible state
// that routes to the create flow instead of a submit nobody can succeed at.
//
// Only the api boundary and the router are mocked, so the picker under test
// is the real useWorkspacePicker every admin panel already uses.
const { workspaces, createTarget } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  createTarget: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { workspaces, createTarget },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

afterEach(() => {
  workspaces.mockReset();
  createTarget.mockReset();
});

describe("NewTargetForm workspace picker", () => {
  it("sends the workspace the user picked, and offers no id field to type into", async () => {
    workspaces.mockResolvedValue([
      { id: 7, name: "prod" },
      { id: 9, name: "staging" },
    ]);
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

  it("points at the create flow instead of a form when no workspace exists", async () => {
    workspaces.mockResolvedValue([]);
    render(<NewTargetForm />);

    const link = await screen.findByRole("link", { name: "Create a workspace" });
    // Plain attribute check: this project does not load jest-dom matchers.
    expect(link.getAttribute("href")).toBe("/workspaces");
    // Nothing to submit: this is the state that used to render a form whose
    // only possible outcome was a 500 reported as a CORS error.
    expect(screen.queryByRole("button", { name: "Add Target" })).toBeNull();
    expect(createTarget).not.toHaveBeenCalled();
  });

  it("says the workspace list failed rather than claiming there are none", async () => {
    // useWorkspacePicker's own reason for existing: a dropped rejection
    // renders as "no workspaces exist", a claim the page has not earned.
    workspaces.mockRejectedValue(new Error("503"));
    render(<NewTargetForm />);

    await screen.findByText(/Could not load workspaces: 503/);
    expect(screen.queryByRole("link", { name: "Create a workspace" })).toBeNull();
  });
});
