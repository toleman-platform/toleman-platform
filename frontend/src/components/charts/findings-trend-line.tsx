"use client";

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import type { FindingsTrendData } from "@/lib/api";

export function FindingsTrendLine({ data }: { data: FindingsTrendData }) {
  if (!data.points || data.points.length === 0) {
    return <p className="flex h-56 items-center justify-center text-sm text-muted-foreground">No data yet</p>;
  }

  const chartData = data.points.map((p) => ({
    date: p.date.slice(5), // MM-DD, year is noise at this zoom level
    open: p.open,
  }));

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--color-accent-strong)" stopOpacity={0.35} />
              <stop offset="95%" stopColor="var(--color-accent-strong)" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.4} />
          <XAxis dataKey="date" tick={{ fill: "var(--color-muted-foreground)", fontSize: 11 }} axisLine={{ stroke: "var(--color-border)" }} />
          <YAxis tick={{ fill: "var(--color-muted-foreground)", fontSize: 11 }} axisLine={{ stroke: "var(--color-border)" }} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--color-popover)",
              border: "1px solid var(--color-border)",
              borderRadius: "8px",
              color: "var(--color-popover-foreground)",
              boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            }}
          />
          <Area
            type="monotone"
            dataKey="open"
            stroke="var(--color-accent-strong)"
            strokeWidth={2.5}
            fill="url(#trendGradient)"
            dot={{ r: 3, fill: "var(--color-accent-strong)", strokeWidth: 1 }}
            activeDot={{ r: 5, stroke: "var(--color-background)", strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
