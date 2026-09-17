import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RemediationRaisePrButton } from "./remediation-raise-pr-button";

// (#247 follow-up) No AI, no diff-review dialog -- one click opens the PR
// directly. These pin down the three states a click can leave the button
// in: still working, opened (a link to the real PR replaces the button),
// and failed (an error shown next to a button the user can still retry).
const { raisePackageFixPr } = vi.hoisted(() => ({ raisePackageFixPr: vi.fn() }));

vi.mock("@/lib/api", () => ({ api: { raisePackageFixPr } }));

beforeEach(() => {
  raisePackageFixPr.mockReset();
});

describe("RemediationRaisePrButton", () => {
  it("shows a loading state while the PR is being raised", async () => {
    let resolveRaise: (value: { pr_url: string; pr_number: number; branch: string }) => void = () => {};
    raisePackageFixPr.mockReturnValue(
      new Promise((resolve) => {
        resolveRaise = resolve;
      }),
    );

    render(<RemediationRaisePrButton targetId={7} packageName="starlette" />);
    fireEvent.click(screen.getByRole("button", { name: "Raise PR" }));

    expect(screen.getByRole("button", { name: "Raising PR..." })).not.toBeNull();

    resolveRaise({ pr_url: "https://github.com/a/b/pull/1", pr_number: 1, branch: "toleman/fix-pkg-1" });
    await waitFor(() => expect(screen.getByRole("link", { name: /View PR/ })).not.toBeNull());
  });

  it("replaces the button with a link to the opened PR on success", async () => {
    raisePackageFixPr.mockResolvedValue({
      pr_url: "https://github.com/a/b/pull/1",
      pr_number: 1,
      branch: "toleman/fix-pkg-1",
    });

    render(<RemediationRaisePrButton targetId={7} packageName="starlette" />);
    fireEvent.click(screen.getByRole("button", { name: "Raise PR" }));

    const link = (await screen.findByRole("link", { name: /View PR/ })) as HTMLAnchorElement;
    expect(link.href).toContain("/a/b/pull/1");
    expect(screen.queryByRole("button", { name: "Raise PR" })).toBeNull();
    expect(raisePackageFixPr).toHaveBeenCalledWith(7, "starlette");
  });

  it("shows the error and leaves a working retry button on failure", async () => {
    raisePackageFixPr.mockRejectedValue(new Error("no GitHub App installed"));

    render(<RemediationRaisePrButton targetId={7} packageName="starlette" />);
    fireEvent.click(screen.getByRole("button", { name: "Raise PR" }));

    expect(await screen.findByText("no GitHub App installed")).not.toBeNull();
    // Not stuck mid-flight, and not silently replaced by a PR link that
    // was never actually opened -- the user can just click again.
    expect(screen.getByRole("button", { name: "Raise PR" })).not.toBeNull();
  });
});
