"use client";

import { useSyncExternalStore } from "react";
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

// Issue #173: bumped from 220x130. The widget spans the full dashboard
// width and the gauge is its headline number, but at 220px it read as an
// afterthought beside the component breakdown. Kept at a 2:1 ratio so the
// semicircle still fills the box (cy sits on the bottom edge).
const CHART_WIDTH = 280;
const CHART_HEIGHT = 160;

export function SecurityScoreGauge({ score, grade }: { score: number; grade: string | null }) {
  const color = grade ? GRADE_COLOR[grade] ?? "var(--color-chart-1)" : "var(--color-muted-foreground)";
  const data = [{ value: score, fill: color }];

  // Recharts derives its <clipPath> ids from a module-global counter, so the
  // ids in the server-rendered HTML never line up with the ones the client
  // generates on hydration ("recharts15-clip" vs "recharts2-clip"); React
  // reported a hydration mismatch and regenerated this whole subtree on
  // every dashboard load. The chart carries no content a crawler or a
  // no-JS reader needs (the score, grade and full component breakdown are
  // all real text next to it), so rendering it after mount is a clean fix
  // rather than a workaround; the wrapper reserves the exact final size so
  // nothing shifts when it appears.
  // useSyncExternalStore is React's supported way to ask "am I on the
  // client?": the server snapshot is false, the client snapshot is true, and
  // it never subscribes to anything. An effect that calls setState would do
  // the same job but costs an extra commit and is what
  // react-hooks/set-state-in-effect flags.
  const mounted = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  );

  return (
    // shrink-0: this sits inside a flex row (widgets.tsx's SecurityScoreWidget)
    // next to the score-breakdown list. The chart box below has a *fixed*
    // pixel width via inline style (CHART_WIDTH), but flexbox's default
    // flex-shrink: 1 still shrinks a fixed-width child when the row runs out
    // of room; the outer div would shrink while the SVG inside it kept its
    // hardcoded width={280} attribute, so the arc silently overflowed past
    // its now-narrower parent and the centered text overlay (which centers
    // against the *shrunk* parent) drifted out of alignment with it. This is
    // exactly the "arc on the left, number/badge floating off to the right"
    // bug reported against this gauge; shrink-0 keeps the box at its real
    // size always; the flex row wraps to a new line instead (see the parent's
    // flex-wrap) rather than distorting the gauge to fit.
    <div className="flex shrink-0 flex-col items-center">
      {/* The number overlay is positioned against the chart box alone. It
          used to be `absolute bottom-0` of a wrapper that also contained the
          grade badge, which put the "/ 100" line directly on top of the
          badge; both were unreadable. */}
      <div className="relative" style={{ width: CHART_WIDTH, height: CHART_HEIGHT }}>
        {mounted && (
          <RadialBarChart
            width={CHART_WIDTH}
            height={CHART_HEIGHT}
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
        )}
        <div
          className="absolute inset-x-0 bottom-0 flex flex-col items-center"
          role="img"
          aria-label={`Security score ${Math.round(score)} out of 100${grade ? `, grade ${grade}` : ""}`}
        >
          <span className="text-3xl font-bold leading-none text-foreground">{Math.round(score)}</span>
          <span className="mt-0.5 text-xs leading-none text-muted-foreground">/ 100</span>
        </div>
      </div>
      {grade && (
        <div
          className="mt-2 flex h-9 w-9 items-center justify-center rounded-full border text-base font-semibold"
          style={{ borderColor: color, color }}
          aria-hidden="true"
        >
          {grade}
        </div>
      )}
    </div>
  );
}
