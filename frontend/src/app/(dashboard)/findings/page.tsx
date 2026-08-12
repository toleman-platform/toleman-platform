import { api } from "@/lib/api";
import { FindingRow } from "@/components/finding-row";

export default async function FindingsPage() {
  const findings = await api.findings().catch(() => []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">All Findings</h1>
        <p className="text-sm text-muted-foreground">{findings.length} findings across all targets</p>
      </div>
      <div className="flex flex-col gap-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
        {findings.length === 0 && <p className="text-sm text-muted-foreground">No findings yet.</p>}
      </div>
    </div>
  );
}
