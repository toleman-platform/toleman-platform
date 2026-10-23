import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LoginPage from "./page";

const navigation = vi.hoisted(() => ({ push: vi.fn(), refresh: vi.fn(), next: "" }));
vi.mock("next/navigation", () => ({
  useRouter: () => navigation,
  useSearchParams: () => new URLSearchParams({ next: navigation.next }),
}));
vi.mock("@/lib/api", () => ({
  api: { login: vi.fn().mockResolvedValue({}) },
  ApiError: class ApiError extends Error {},
  NetworkError: class NetworkError extends Error {},
}));

async function submitLogin() {
  render(<LoginPage />);
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "test@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign In" }));
  await waitFor(() => expect(navigation.push).toHaveBeenCalled());
}

describe("login return destination", () => {
  beforeEach(() => vi.clearAllMocks());

  it.each([
    "javascript:window.__loginCanary=1",
    "java\tscript:window.__loginCanary=1",
    "https://example.com/phishing",
    "//example.com/phishing",
    "/\\example.com/phishing",
    "/\n/example.com/phishing",
    "/a/..//example.com/phishing",
    "data:text/html,<script>alert(1)</script>",
  ])("rejects unsafe next=%s", async (destination) => {
    navigation.next = destination;
    await submitLogin();
    expect(navigation.push).toHaveBeenCalledWith("/");
  });

  it("preserves a dashboard deep link and its query", async () => {
    navigation.next = "/pr-history?target_id=2&ignore_finding=144#review";
    await submitLogin();
    expect(navigation.push).toHaveBeenCalledWith(navigation.next);
  });
});
