export const SEVERITY_COLOR: Record<string, string> = {
  Critical: "bg-red-950 text-red-300 border-red-800",
  High: "bg-orange-950 text-orange-300 border-orange-800",
  Medium: "bg-yellow-950 text-yellow-300 border-yellow-800",
  Low: "bg-blue-950 text-blue-300 border-blue-800",
  Informational: "bg-neutral-900 text-neutral-400 border-neutral-700",
};

export const STATE_COLOR: Record<string, string> = {
  Open: "text-red-300",
  "Accepted Risk": "text-yellow-300",
  "False Positive": "text-neutral-400",
  "Won't Fix": "text-neutral-400",
  Mitigated: "text-green-400",
  Reopened: "text-orange-300",
};
