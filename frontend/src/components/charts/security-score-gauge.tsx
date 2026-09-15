"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

// Issue #63: single-number security health gauge.
const GRADE_COLOR: Record<string, string> = {
  A: "var(--color-chart-5)",
  B: "var(--color-chart-5)",
  C: "var(--color-chart-3)",
  D: "var(--color-chart-3)",
  F: "var(--color-destructive)",
};

const GRADE_STYLES: Record<string, string> = {
  A: "border-chart-5/30 bg-chart-5/10 text-chart-5",
  B: "border-chart-5/30 bg-chart-5/10 text-chart-5",
  C: "border-chart-3/30 bg-chart-3/10 text-chart-3",
  D: "border-chart-3/30 bg-chart-3/10 text-chart-3",
  F: "border-destructive/30 bg-destructive/10 text-destructive",
};

const GRADE_LABELS: Record<string, string> = {
  A: "Healthy",
  B: "Good",
  C: "Moderate",
  D: "High Risk",
  F: "Critical",
};

export function SecurityScoreGauge({ score, grade }: { score: number; grade: string | null }) {
  const normalizedScore = Math.min(100, Math.max(0, score));
  const targetScore = Math.round(normalizedScore);
  const color = grade ? GRADE_COLOR[grade] ?? "var(--color-chart-1)" : "var(--color-muted-foreground)";

  // Geometry. The svg is 240x125 with a 1:1 viewBox, so every number below is
  // both an svg user unit and a CSS pixel inside the positioned wrapper, and
  // the two coordinate systems cannot drift apart.
  //
  // Arc: centre (120, 80), r = 70, stroke 10, a 230 degree sweep rotated 155
  // degrees so the gap sits symmetrically at the bottom. That puts the
  // painted ring between y = 5 (top of the stroke) and y = 114.6 (outer edge
  // of the two lower endpoints).
  //
  // Optical centring of the numeral: the ring's own bounding box is centred
  // at y = 59.8, the circle at y = 80. A shape that is open at the bottom
  // reads as if its middle were above the true circle centre, but not as far
  // up as the bounding box suggests, so the numeral's ink is centred between
  // the two, at y = 70. With `leading-none` a digit's ink centre sits
  // essentially at its own line box centre, so a 42px line box starting at
  // y = 49 lands the ink where it is wanted. The "out of 100" caption then
  // hangs below it, which balances the numeral + caption pair back onto the
  // circle centre without moving the numeral itself off the optical one.
  const radius = 70;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius; // ~439.82
  const arcDegrees = 230;
  const maxArcLength = (arcDegrees / 360) * circumference; // ~281.0

  // Smooth entrance states
  const [animatedScore, setAnimatedScore] = useState(0);
  const [hasMounted, setHasMounted] = useState(false);

  useEffect(() => {
    let frameId: number;
    let animFrameId: number;
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (prefersReducedMotion) {
      frameId = requestAnimationFrame(() => {
        setAnimatedScore(targetScore);
        setHasMounted(true);
      });
      return () => cancelAnimationFrame(frameId);
    }

    frameId = requestAnimationFrame(() => {
      setHasMounted(true);
    });

    const startTime = performance.now();
    const duration = 800;

    function animate(currentTime: number) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(easeProgress * targetScore));

      if (progress < 1) {
        animFrameId = requestAnimationFrame(animate);
      }
    }

    animFrameId = requestAnimationFrame(animate);
    return () => {
      cancelAnimationFrame(frameId);
      cancelAnimationFrame(animFrameId);
    };
  }, [targetScore]);

  const activeLength = (normalizedScore / 100) * maxArcLength;
  const strokeDashoffset = hasMounted ? maxArcLength - activeLength : maxArcLength;

  return (
    // No fixed height: the svg and the grade badge define it between them, so
    // a gauge without a grade does not reserve a band of empty space under
    // itself. `shrink-0` keeps the fixed-size arc out of flexbox's default
    // shrink, which would squash the ring away from the numeral.
    <div className="relative flex w-60 shrink-0 flex-col items-center">
      <svg
        width={240}
        height={125}
        viewBox="0 0 240 125"
        className="overflow-visible"
        role="img"
        aria-label={`Security score ${targetScore} out of 100${grade ? `, grade ${grade}${GRADE_LABELS[grade] ? ` (${GRADE_LABELS[grade]})` : ""}` : ""}`}
      >
        {/* Background track (230 degree arc, rotated 155 so the gap is symmetrical at the bottom) */}
        <circle
          cx={120}
          cy={80}
          r={radius}
          fill="none"
          stroke="var(--color-secondary)"
          strokeWidth={strokeWidth}
          strokeDasharray={`${maxArcLength} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(155 120 80)"
        />
        {/* Active progress arc animating via hardware-accelerated strokeDashoffset */}
        <circle
          cx={120}
          cy={80}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={`${maxArcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          transform="rotate(155 120 80)"
          style={{
            transition: "stroke-dashoffset 850ms cubic-bezier(0.16, 1, 0.3, 1)",
          }}
        />
      </svg>

      {/* `top-[49px]` and `text-[42px]` are svg-coordinate geometry, not
          spacing or type tokens: they are derived in the comment above from
          the arc's own centre and radius, and they have to move together
          with it. A single fixed numeral size on purpose -- the arc is a
          fixed 240px wide at every viewport, so a responsive size here only
          ever shifted the number off the centre it was aligned to. */}
      <div className="pointer-events-none absolute inset-x-0 top-[49px] flex flex-col items-center">
        <span className="font-tabular text-[42px] leading-none font-extrabold tracking-tight text-foreground">
          {animatedScore}
        </span>
        <span className="text-micro mt-0.5 font-tabular text-muted-foreground">out of 100</span>
      </div>

      {grade && (
        <div
          className={cn(
            "mt-2 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide",
            GRADE_STYLES[grade] ?? "border-border bg-secondary text-foreground"
          )}
        >
          <span>Grade {grade}</span>
          {GRADE_LABELS[grade] && (
            <>
              <span className="opacity-40">&middot;</span>
              <span className="font-medium opacity-90">{GRADE_LABELS[grade]}</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}
