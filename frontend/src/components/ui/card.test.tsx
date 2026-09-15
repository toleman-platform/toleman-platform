import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Card, CardContent, CardHeader, CardTitle } from "./card";

describe("CardTitle", () => {
  // core lows: this rendered a <div>, so every page built from cards had no
  // heading in its accessibility tree -- a screen reader's "next heading"
  // navigation found nothing on a page made entirely of Cards.
  it("renders as a heading by default, not a div", () => {
    render(<CardTitle>Spacing, Grid & Proportions</CardTitle>);
    const heading = screen.getByRole("heading", { name: "Spacing, Grid & Proportions" });
    expect(heading.tagName).toBe("H2");
  });

  it("lets a caller choose a different level for the rare page that needs one", () => {
    render(<CardTitle as="h3">Sub-section</CardTitle>);
    expect(screen.getByRole("heading", { level: 3, name: "Sub-section" })).not.toBeNull();
  });

  it("keeps working inside a full Card without changing what's on screen", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Live Scan Activity</CardTitle>
        </CardHeader>
        <CardContent>3 scans running</CardContent>
      </Card>,
    );
    expect(screen.getByRole("heading", { name: "Live Scan Activity" })).not.toBeNull();
    expect(screen.getByText("3 scans running")).not.toBeNull();
  });
});
