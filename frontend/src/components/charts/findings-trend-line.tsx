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
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="date" tick={{ fill: "#94a3b8", fontSize: 12 }} axisLine={{ stroke: "#1e293b" }} />
          <YAxis tick={{ fill: "#94a3b8", fontSize: 12 }} axisLine={{ stroke: "#1e293b" }} allowDecimals={false} />
          <Tooltip contentStyle={{ backgroundColor: "#111827", border: "1px solid #1e293b", borderRadius: "8px", color: "#e2e8f0" }} />
          <Line type="monotone" dataKey="open" stroke="#06b6d4" strokeWidth={2} dot={{ r: 3, fill: "#06b6d4" }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
