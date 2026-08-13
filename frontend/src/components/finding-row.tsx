"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
import { Finding, FindingEnrichment, api, githubBlobUrl } from "@/lib/api";
import {
  EPSS_BADGE_COLOR,
  EPSS_NOTABLE_THRESHOLD,
  KEV_BADGE_COLOR,
  SEVERITY_BORDER_COLOR,
  SEVERITY_COLOR,
  STATE_COLOR,
} from "@/lib/severity";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

// GET /api/findings/{id}/enrichment (issue #71) -- real CVE/CWE/CVSS/fix-
// version data sourced from NVD + OSV.dev, no AI provider involved. Lazily
// fetched the first time a finding's details are expanded, then cached in
// component state so re-expanding doesn't re-hit the network.
function FindingEnrichmentPanel({ finding }: { finding: Finding }) {
  const [enrichment, setEnrichment] = useState<FindingEnrichment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .findingEnrichment(finding.id)
      .then((data) => {
        if (!cancelled) setEnrichment(data);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "enrichment lookup failed");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  if (loading) {
    return <p className="text-xs text-muted-foreground">Loading enrichment...</p>;
  }
  if (error) {
    return <p className="text-xs text-destructive">{error}</p>;
  }
  if (!enrichment || !enrichment.cve_id) {
    // No CVE on this finding (SAST/secrets finding) -- nothing to show here.
    return null;
  }

  const hasData =
    enrichment.cve_description || enrichment.cvss_score !== null || (enrichment.cwe_ids && enrichment.cwe_ids.length > 0) ||
    (enrichment.fix_versions && enrichment.fix_versions.length > 0) || (enrichment.references && enrichment.references.length > 0);

  return (
    <div className="mt-3 rounded-md border border-border bg-secondary/40 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Vulnerability Details</span>
        <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-muted-foreground" title="Sourced from public data (NVD/OSV.dev) -- no AI involved">
          no AI · MITRE/NVD/OSV.dev
        </Badge>
      </div>

      {!hasData && (
        <p className="text-xs text-muted-foreground">No additional public data found for {enrichment.cve_id} yet.</p>
      )}

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {enrichment.cvss_score !== null && (
          <div>
            <span className="text-xs font-medium text-foreground">CVSS Score: </span>
            <span className="text-xs text-muted-foreground">{enrichment.cvss_score.toFixed(1)}</span>
            {enrichment.cvss_vector && (
              <span className="ml-1 font-mono text-[11px] text-muted-foreground">({enrichment.cvss_vector})</span>
            )}
          </div>
        )}
        {enrichment.cwe_ids && enrichment.cwe_ids.length > 0 && (
          <div>
            <span className="text-xs font-medium text-foreground">CWE: </span>
            {enrichment.cwe_ids.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="mr-1 text-xs text-primary underline"
              >
                {cwe}
              </a>
            ))}
          </div>
        )}
      </div>

      {enrichment.cve_description && (
        <p className="mt-2 text-xs text-muted-foreground">{enrichment.cve_description}</p>
      )}

      {enrichment.fix_versions && enrichment.fix_versions.length > 0 && (
        <div className="mt-2">
          <span className="text-xs font-medium text-foreground">Fixed in: </span>
          <span className="text-xs text-muted-foreground">
            {enrichment.fix_versions
              .map((f) => {
                const pkg = f.package ? `${f.package}${f.ecosystem ? ` (${f.ecosystem})` : ""} ` : "";
                return `${pkg}≥ ${f.fixed}`;
              })
              .join(", ")}
          </span>
        </div>
      )}

      {enrichment.references && enrichment.references.length > 0 && (
        <div className="mt-2">
          <span className="text-xs font-medium text-foreground">References: </span>
          <div className="mt-1 flex flex-col gap-0.5">
            {enrichment.references.slice(0, 5).map((url) => (
              <a
                key={url}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="truncate text-xs text-primary underline"
              >
                {url}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function FindingRow({
  finding,
  repoUrl,
  selectable = false,
  selected = false,
  onSelectChange,
}: {
  finding: Finding;
  repoUrl?: string;
  selectable?: boolean;
  selected?: boolean;
  onSelectChange?: (checked: boolean) => void;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);

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
    <Card className={`border-border bg-card border-l-4 ${SEVERITY_BORDER_COLOR[finding.severity]}`}>
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-start gap-3">
            {selectable && (
              <input
                type="checkbox"
                aria-label={`Select finding ${finding.title}`}
                className="mt-1 h-4 w-4 shrink-0 accent-primary"
                checked={selected}
                onChange={(e) => onSelectChange?.(e.target.checked)}
              />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Badge
                  variant="outline"
                  className={`shrink-0 px-2 py-0.5 text-sm font-bold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity]}`}
                >
                  {finding.severity}
                </Badge>
                {finding.kev_listed && (
                  <Badge
                    variant="outline"
                    title="Listed in CISA's Known Exploited Vulnerabilities catalog"
                    className={`shrink-0 px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${KEV_BADGE_COLOR}`}
                  >
                    KEV
                  </Badge>
                )}
                {!finding.kev_listed && finding.epss_score !== null && finding.epss_score > EPSS_NOTABLE_THRESHOLD && (
                  <Badge
                    variant="outline"
                    title="EPSS: predicted probability of real-world exploitation in the next 30 days"
                    className={`shrink-0 px-2 py-0.5 text-xs font-bold ${EPSS_BADGE_COLOR}`}
                  >
                    EPSS {(finding.epss_score * 100).toFixed(0)}%
                  </Badge>
                )}
                <button
                  onClick={() => setDetailsOpen((v) => !v)}
                  className="flex min-w-0 items-center gap-1 truncate text-left text-sm font-medium text-foreground hover:underline"
                  title="Show details"
                >
                  {detailsOpen ? (
                    <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
                  )}
                  <span className="truncate">{finding.title}</span>
                </button>
              </div>
              <div className="mt-1 flex items-center gap-1 truncate text-xs text-muted-foreground">
                <span className="truncate">
                  {finding.tool} · {finding.file_path}
                  {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
                </span>
                {repoUrl && finding.file_path && (
                  <a
                    href={githubBlobUrl(repoUrl, finding.branch, finding.file_path, finding.line_start)}
                    target="_blank"
                    rel="noopener noreferrer"
                    title="Open this line on GitHub"
                    onClick={(e) => e.stopPropagation()}
                    className="shrink-0 text-muted-foreground hover:text-foreground"
                  >
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="font-mono text-sm text-foreground">{finding.priority_score}</div>
            <div className={`text-xs ${STATE_COLOR[finding.state] || "text-muted-foreground"}`}>{finding.state}</div>
          </div>
        </div>

        {detailsOpen && (
          <div className="mt-2">
            {finding.description && <p className="text-xs text-muted-foreground">{finding.description}</p>}
            <FindingEnrichmentPanel finding={finding} />
          </div>
        )}

        <div className="mt-2">
          {!open ? (
            <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
              Triage
            </button>
          ) : (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Input
                className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
                placeholder="Reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
              {TRIAGE_STATES.map((s) => (
                <Button key={s} size="sm" variant="outline" disabled={submitting} onClick={() => triage(s)} className="h-7 text-xs">
                  {s}
                </Button>
              ))}
              <button onClick={() => setOpen(false)} className="text-xs text-muted-foreground">
                cancel
              </button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
