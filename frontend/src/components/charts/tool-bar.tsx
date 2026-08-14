"use client";

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function ToolBar({ data }: { data: Record<string, number> }) {
  const chartData = Object.entries(data).map(([name, count]) => ({ name, count }));

  if (chartData.length === 0) {
    return <p className="flex h-56 items-center justify-center text-sm text-muted-foreground">No open findings yet</p>;
  }

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
          <XAxis dataKey="name" tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} axisLine={{ stroke: "var(--color-border)" }} />
          <YAxis tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} axisLine={{ stroke: "var(--color-border)" }} allowDecimals={false} />
          <Tooltip contentStyle={{ backgroundColor: "var(--color-popover)", border: "1px solid var(--color-border)", borderRadius: "8px", color: "var(--color-popover-foreground)" }} />
          <Bar dataKey="count" fill="var(--color-accent-strong)" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
