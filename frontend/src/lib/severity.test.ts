import { describe, expect, it } from "vitest";
import { SEVERITY_COLOR, SEVERITY_HEX, STATE_COLOR } from "./severity";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
const STATES = ["Open", "Accepted Risk", "False Positive", "Won't Fix", "Mitigated", "Reopened"];

describe("severity color maps", () => {
  it("has a color class for every severity", () => {
    for (const s of SEVERITIES) {
      expect(SEVERITY_COLOR[s]).toBeTruthy();
    }
  });

  it("has a themed color token for every severity", () => {
    // #115: these are CSS var() references (not literal hex) so severity
    // colors stay theme-aware in chart contexts too; see the comment on
    // SEVERITY_HEX in severity.ts.
    for (const s of SEVERITIES) {
      expect(SEVERITY_HEX[s]).toMatch(/^var\(--[\w-]+\)$/);
    }
  });

  it("has a color class for every triage state", () => {
    for (const s of STATES) {
      expect(STATE_COLOR[s]).toBeTruthy();
    }
  });

  it("critical is visually distinct from low", () => {
    expect(SEVERITY_HEX["Critical"]).not.toBe(SEVERITY_HEX["Low"]);
  });
});
