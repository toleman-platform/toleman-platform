import Link from "next/link";
import { api } from "@/lib/api";
import { SEVERITY_COLOR } from "@/lib/severity";

export default async function PosturePage() {
  const [summary, posture] = await Promise.all([
    api.summary().catch(() => ({ total: 0, open: 0, mitigated: 0 })),
    api.posture().catch(() => []),
  ]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold">Main Posture Dashboard</h1>
        <p className="text-neutral-400 text-sm mt-1">
          Organizational health, default branches only.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Stat label="Total Findings" value={summary.total} />
        <Stat label="Open" value={summary.open} accent="text-red-400" />
        <Stat label="Mitigated" value={summary.mitigated} accent="text-green-400" />
      </div>

      <div>
        <h2 className="text-sm font-medium text-neutral-400 mb-3">Targets</h2>
        {posture.length === 0 && (
          <p className="text-neutral-500 text-sm">
            No targets yet. Add one on the{" "}
            <Link href="/targets" className="underline">
              Targets
            </Link>{" "}
            page.
          </p>
        )}
        <div className="space-y-3">
          {posture.map(({ target, breakdown }) => (
            <Link
              key={target.id}
              href={`/targets/${target.id}`}
              className="block border border-neutral-800 rounded-lg p-4 hover:border-neutral-600 transition"
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-medium">{target.name}</span>
                  <span className="text-neutral-500 text-xs ml-2">
                    {target.label} · weight {target.criticality_weight}
                  </span>
                </div>
                <div className="flex gap-2">
                  {Object.entries(breakdown).map(([severity, states]) => {
                    const openCount = states["Open"] || 0;
                    if (openCount === 0) return null;
                    return (
                      <span
                        key={severity}
                        className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLOR[severity]}`}
                      >
                        {severity}: {openCount}
                      </span>
                    );
                  })}
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="border border-neutral-800 rounded-lg p-4">
      <div className={`text-2xl font-semibold ${accent || ""}`}>{value}</div>
      <div className="text-xs text-neutral-500 mt-1">{label}</div>
    </div>
  );
}
