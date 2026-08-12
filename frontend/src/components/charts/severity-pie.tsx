"use client";

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { SEVERITY_HEX } from "@/lib/severity";

const ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

export function SeverityPie({ data }: { data: Record<string, number> }) {
  const entries = ORDER.filter((k) => data[k]).map((k) => ({ name: k, value: data[k], color: SEVERITY_HEX[k] }));

  if (entries.length === 0) {
    return <p className="flex h-56 items-center justify-center text-sm text-muted-foreground">No open findings</p>;
  }

  return (
    <>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={entries} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" stroke="none">
              {entries.map((e) => (
                <Cell key={e.name} fill={e.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ backgroundColor: "#111827", border: "1px solid #1e293b", borderRadius: "8px", color: "#e2e8f0" }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap justify-center gap-3">
        {entries.map((e) => (
          <div key={e.name} className="flex items-center gap-1.5">
            <div className="h-2 w-2 rounded-full" style={{ backgroundColor: e.color }} />
            <span className="text-[10px] text-muted-foreground">
              {e.name}: {e.value}
            </span>
          </div>
        ))}
      </div>
    </>
  );
}
