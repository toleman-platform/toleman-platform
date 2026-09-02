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

  // Geometry: 230° arc.
  // Center is at (120, 80) inside 240x160.
  // Radius = 70, stroke = 10.
  // Top of arc is at y = 5px, endpoints at y = 115px.
  // Number is centered inside the dome at y ≈ 74px.
  // Legend badge sits right below the arc at y = 125px (10px clean gap).
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
    <div className="flex shrink-0 flex-col items-center justify-center">
      <div className="relative flex flex-col items-center" style={{ width: 240, height: 160 }}>
        <svg
          width={240}
          height={125}
          viewBox="0 0 240 125"
          className="overflow-visible"
          role="img"
          aria-label={`Security score ${targetScore} out of 100${grade ? `, grade ${grade}${GRADE_LABELS[grade] ? ` (${GRADE_LABELS[grade]})` : ""}` : ""}`}
        >
          {/* Background track (230° arc, rotated 155° so gap is symmetrical at bottom) */}
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

        {/* Center content: optically centered in the interior dome */}
        <div
          className="absolute inset-x-0 flex flex-col items-center justify-center pointer-events-none"
          style={{ top: 24, height: 84 }}
        >
          <span className="text-4xl sm:text-[44px] font-extrabold font-tabular tracking-tight text-foreground leading-none">
            {animatedScore}
          </span>
          <span className="mt-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground font-tabular">
            out of 100
          </span>
        </div>

        {/* Legend badge positioned close under the arc cradle with clean ~12px spacing */}
        {grade && (
          <div className="mt-0.5 flex justify-center">
            <div
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide shadow-2xs",
                GRADE_STYLES[grade] ?? "border-border bg-secondary text-foreground"
              )}
            >
              <span>Grade {grade}</span>
              {GRADE_LABELS[grade] && (
                <>
                  <span className="opacity-40">·</span>
                  <span className="font-medium opacity-90">{GRADE_LABELS[grade]}</span>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
