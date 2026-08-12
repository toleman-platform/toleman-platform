import { api } from "@/lib/api";
import { FindingRow } from "@/components/finding-row";

export default async function FindingsPage() {
  const findings = await api.findings().catch(() => []);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">All Findings ({findings.length})</h1>
      <div className="space-y-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
        {findings.length === 0 && (
          <p className="text-neutral-500 text-sm">No findings yet.</p>
        )}
      </div>
    </div>
  );
}
