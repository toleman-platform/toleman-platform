import { api } from "@/lib/api";
import { ScanButtons } from "./scan-buttons";
import { FindingRow } from "@/components/finding-row";

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const targetId = Number(id);
  const [target, findings] = await Promise.all([
    api.target(targetId),
    api.findings(targetId),
  ]);

  return (
    <div className="space-y-8">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold">{target.name}</h1>
          <p className="text-neutral-400 text-sm mt-1">{target.repo_url}</p>
          <p className="text-neutral-500 text-xs mt-1">
            {target.label} · criticality weight {target.criticality_weight} · branch {target.default_branch}
          </p>
        </div>
        <ScanButtons targetId={targetId} />
      </div>

      <div>
        <h2 className="text-sm font-medium text-neutral-400 mb-3">
          Findings ({findings.length})
        </h2>
        <div className="space-y-2">
          {findings.map((f) => (
            <FindingRow key={f.id} finding={f} />
          ))}
          {findings.length === 0 && (
            <p className="text-neutral-500 text-sm">
              No findings yet. Run a scan above.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
