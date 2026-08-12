import Link from "next/link";
import { api } from "@/lib/api";
import { NewTargetForm } from "./new-target-form";

export default async function TargetsPage() {
  const targets = await api.targets().catch(() => []);

  return (
    <div className="space-y-8">
      <h1 className="text-xl font-semibold">Targets</h1>

      <NewTargetForm />

      <div className="space-y-2">
        {targets.map((t) => (
          <Link
            key={t.id}
            href={`/targets/${t.id}`}
            className="flex items-center justify-between border border-neutral-800 rounded-lg p-4 hover:border-neutral-600 transition"
          >
            <div>
              <div className="font-medium">{t.name}</div>
              <div className="text-xs text-neutral-500">{t.repo_url}</div>
            </div>
            <span className="text-xs text-neutral-400">{t.label} · weight {t.criticality_weight}</span>
          </Link>
        ))}
        {targets.length === 0 && (
          <p className="text-neutral-500 text-sm">No targets yet.</p>
        )}
      </div>
    </div>
  );
}
