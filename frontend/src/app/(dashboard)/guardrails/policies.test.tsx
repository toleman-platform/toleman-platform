import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Policies } from "./policies";

/**
 * M14: the rule-type `<select>` used to show only each type's own label
 * ("Block severity threshold", "Suppress rule", "Suppress license") with
 * nothing said about what choosing one actually does -- and the three do
 * genuinely different things (one moves a blocking threshold; the other two
 * remove findings from every scan in the workspace outright). These assert
 * a description renders for whichever type is selected, and that the three
 * descriptions are not interchangeable copy-paste.
 */

const { workspaces, listPolicies, createPolicy, deletePolicy } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  listPolicies: vi.fn(),
  createPolicy: vi.fn(),
  deletePolicy: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { workspaces, listPolicies, createPolicy, deletePolicy },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

afterEach(() => {
  workspaces.mockReset();
  listPolicies.mockReset();
  createPolicy.mockReset();
  deletePolicy.mockReset();
});

describe("Policies, rule type explanations", () => {
  it("explains what the selected rule type does, differently for each of the three", async () => {
    workspaces.mockResolvedValue([{ id: 1, name: "Acme", organization_id: 1, enforcement_mode: null }]);
    listPolicies.mockResolvedValue([]);

    render(<Policies />);

    const select = await screen.findByLabelText("Rule type");

    // Snapshot the TEXT, never the element: the explanation is one node that
    // React re-renders in place, so a ref captured before a change reads the
    // text AFTER it -- which makes every one of these comparisons pass
    // vacuously by comparing a string to itself.
    const blockSeverityText = (await screen.findByText(/PR Guardrail block a pull request/)).textContent;

    fireEvent.change(select, { target: { value: "suppress_rule" } });
    const suppressRuleText = (await screen.findByText(/removes every finding whose rule_id matches/i)).textContent;
    expect(suppressRuleText).not.toBe(blockSeverityText);

    fireEvent.change(select, { target: { value: "suppress_license" } });
    const suppressLicenseText = (await screen.findByText(/Same effect as Suppress rule/)).textContent;
    expect(suppressLicenseText).not.toBe(suppressRuleText);
    expect(suppressLicenseText).not.toBe(blockSeverityText);
  });
});
