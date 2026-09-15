import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { UserManagement } from "./user-management";

/**
 * M18: both role `<select>`s (the "create user" form and each row's role
 * picker) used to render the wire-format role strings verbatim --
 * `security_engineer` as the option text a reader actually sees, not a label
 * anyone chose. These assert a human label is on screen instead of the raw
 * enum value, for both selects.
 */

const { users, createUser, updateUserRole, deleteUser } = vi.hoisted(() => ({
  users: vi.fn(),
  createUser: vi.fn(),
  updateUserRole: vi.fn(),
  deleteUser: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { users, createUser, updateUserRole, deleteUser },
}));

afterEach(() => {
  users.mockReset();
  createUser.mockReset();
  updateUserRole.mockReset();
  deleteUser.mockReset();
});

describe("UserManagement, role labels", () => {
  it("shows a readable label for security_engineer in the new-user role select, not the raw enum value", async () => {
    users.mockResolvedValue([]);
    render(<UserManagement />);

    const select = screen.getByLabelText("New user role") as HTMLSelectElement;
    const optionTexts = Array.from(select.options).map((o) => o.text);

    expect(optionTexts).toContain("Security engineer");
    expect(optionTexts).not.toContain("security_engineer");
  });

  it("shows a readable label in a user's own role select, not the raw enum value", async () => {
    users.mockResolvedValue([{ id: 1, name: "Ada Lovelace", email: "ada@example.com", role: "security_engineer" }]);
    render(<UserManagement />);

    const select = (await screen.findByLabelText("Role for Ada Lovelace")) as HTMLSelectElement;
    const optionTexts = Array.from(select.options).map((o) => o.text);

    expect(select.value).toBe("security_engineer");
    expect(optionTexts).toContain("Security engineer");
    expect(optionTexts).not.toContain("security_engineer");
  });
});
