"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Finding, api } from "@/lib/api";
import { SEVERITY_COLOR, STATE_COLOR } from "@/lib/severity";

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

export function FindingRow({ finding }: { finding: Finding }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function triage(toState: string) {
    setSubmitting(true);
    try {
      await api.triage(finding.id, toState, reason);
      setOpen(false);
      setReason("");
      router.refresh();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="border border-neutral-800 rounded-lg p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={`text-xs px-2 py-0.5 rounded border shrink-0 ${SEVERITY_COLOR[finding.severity]}`}>
              {finding.severity}
            </span>
            <span className="text-sm font-medium truncate">{finding.title}</span>
          </div>
          <div className="text-xs text-neutral-500 mt-1 truncate">
            {finding.tool} · {finding.file_path}
            {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-sm font-mono">{finding.priority_score}</div>
          <div className={`text-xs ${STATE_COLOR[finding.state] || "text-neutral-400"}`}>{finding.state}</div>
        </div>
      </div>

      <div className="mt-2">
        {!open ? (
          <button onClick={() => setOpen(true)} className="text-xs text-neutral-400 hover:text-white underline">
            Triage
          </button>
        ) : (
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <input
              className="bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-xs flex-1 min-w-[160px]"
              placeholder="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            {TRIAGE_STATES.map((s) => (
              <button
                key={s}
                onClick={() => triage(s)}
                disabled={submitting}
                className="text-xs border border-neutral-700 rounded px-2 py-1 hover:border-neutral-500 disabled:opacity-50"
              >
                {s}
              </button>
            ))}
            <button onClick={() => setOpen(false)} className="text-xs text-neutral-500">
              cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
