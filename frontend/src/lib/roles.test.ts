import { describe, expect, it } from "vitest";
import { canSeeAdminOnly } from "./roles";

/**
 * This gate decides what appears in the sidebar and on the Administration
 * index. It was previously written out by hand in both places with a comment
 * asking that they be kept in sync; a drift between them would not fail
 * anything, it would just mean one surface lists a destination the other
 * hides.
 */
describe("canSeeAdminOnly", () => {
  it("admits the two roles that administer the platform", () => {
    expect(canSeeAdminOnly("admin")).toBe(true);
    expect(canSeeAdminOnly("security_engineer")).toBe(true);
  });

  it("does not admit the roles that only read", () => {
    expect(canSeeAdminOnly("developer")).toBe(false);
    expect(canSeeAdminOnly("viewer")).toBe(false);
    expect(canSeeAdminOnly("user")).toBe(false);
  });

  it("treats an unreadable role as not admitted, without claiming it is a denial", () => {
    // The caller is expected to say the role could not be read rather than
    // present a shortened list as complete; this function only answers the
    // narrow question.
    expect(canSeeAdminOnly(null)).toBe(false);
    expect(canSeeAdminOnly(undefined)).toBe(false);
    expect(canSeeAdminOnly("")).toBe(false);
  });

  it("is not fooled by a role name that collides with Object.prototype", () => {
    expect(canSeeAdminOnly("constructor")).toBe(false);
    expect(canSeeAdminOnly("toString")).toBe(false);
  });
});
