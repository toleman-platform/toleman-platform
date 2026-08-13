"use client";

import { RadialBar, RadialBarChart, PolarAngleAxis } from "recharts";

// Issue #63: single-number security health gauge. Three-tier color by
// letter grade (A/B -> healthy, C/D -> needs attention, F -> critical) using
// the same CSS custom-property tokens as the rest of the dashboard's charts
// (chart-5/chart-3/destructive) so this stays in sync with the theme.
const GRADE_COLOR: Record<string, string> = {
  A: "var(--color-chart-5)",
  B: "var(--color-chart-5)",
  C: "var(--color-chart-3)",
  D: "var(--color-chart-3)",
  F: "var(--color-destructive)",
};

export function SecurityScoreGauge({ score, grade }: { score: number; grade: string | null }) {
  const color = grade ? GRADE_COLOR[grade] ?? "var(--color-chart-1)" : "var(--color-muted-foreground)";
  const data = [{ value: score, fill: color }];

  return (
    <div className="relative flex flex-col items-center">
      <RadialBarChart
        width={220}
        height={130}
        cx="50%"
        cy="100%"
        innerRadius="72%"
        outerRadius="100%"
        startAngle={180}
        endAngle={0}
        data={data}
        barSize={18}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar background={{ fill: "var(--color-secondary)" }} dataKey="value" cornerRadius={9} />
      </RadialBarChart>
      <div className="absolute bottom-0 flex flex-col items-center">
        <span className="text-3xl font-bold text-foreground">{Math.round(score)}</span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>
      {grade && (
        <div
          className="-mt-2 flex h-9 w-9 items-center justify-center rounded-full border text-base font-semibold"
          style={{ borderColor: color, color }}
        >
          {grade}
        </div>
      )}
    </div>
  );
}
