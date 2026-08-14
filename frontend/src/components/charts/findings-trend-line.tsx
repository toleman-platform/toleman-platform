"use client";

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
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
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
          <XAxis dataKey="date" tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} axisLine={{ stroke: "var(--color-border)" }} />
          <YAxis tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} axisLine={{ stroke: "var(--color-border)" }} allowDecimals={false} />
          <Tooltip contentStyle={{ backgroundColor: "var(--color-popover)", border: "1px solid var(--color-border)", borderRadius: "8px", color: "var(--color-popover-foreground)" }} />
          <Line type="monotone" dataKey="open" stroke="var(--color-accent-strong)" strokeWidth={2} dot={{ r: 3, fill: "var(--color-accent-strong)" }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
