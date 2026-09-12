"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import { ExternalLink, GitPullRequest, Info, X } from "lucide-react";
import { Finding, FindingEnrichment, FindingSuggestFix, RaiseFixPrResult, api, githubBlobUrl } from "@/lib/api";
import { safeHref } from "@/lib/utils";
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { TruncateTooltip } from "@/components/ui/truncate-tooltip";
import { CriticalityChip } from "@/components/criticality-chip";

// Issue #117: the risk/priority score was a bare number (360, 320, 240...)
// with no explanation of what it meant. Mirrors the real formula in
// backend/app/core/scoring.py::compute_priority_score verbatim, severity
// weight (1-5) x target criticality weight (1-5) x 40, capped at 1000, then
// floored to 900 for a CISA KEV-listed CVE or bumped +160 when EPSS predicts
// >50% real-world exploit probability. Kept in one place so the tooltip
// copy can't drift from the scoring module if that formula changes.
const RISK_SCORE_MAX = 1000;
const RISK_SCORE_EXPLANATION =
  "Severity × target criticality × 40, capped at 1000. " +
  "Raised to a floor of 900 for CISA KEV-listed (known exploited) vulnerabilities, " +
  "or boosted when EPSS predicts >50% real-world exploit probability in the next 30 days. " +
  // (UI-04) An external review found every High finding rendering an
  // identical 320/1000 and concluded the column was decorative. It wasn't;
  // the repo scanned was a single target at one criticality weight, so the
  // formula genuinely collapses to a constant. Saying so is the difference
  // between "this feature is broken" and "this needs more than one repo".
  "Findings of the same severity on repos of the same criticality score the same by design \u2014 " +
  "set differing criticality weights per target for the score to separate them.";

function RiskScore({ score }: { score: number }) {
  return (
    <div className="flex flex-col items-end">
      <div className="flex items-center gap-1">
        <span className="font-mono text-sm font-bold text-foreground">{score}</span>
        <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground">/{RISK_SCORE_MAX}</span>
        <Tooltip>
          <TooltipTrigger asChild>
            <button type="button" aria-label="What is the risk score?" onClick={(e) => e.stopPropagation()}>
              <Info className="h-3 w-3 text-muted-foreground hover:text-foreground" />
            </button>
          </TooltipTrigger>
          <TooltipContent className="max-w-[260px] whitespace-normal text-left">{RISK_SCORE_EXPLANATION}</TooltipContent>
        </Tooltip>
      </div>
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Risk score</span>
    </div>
  );
}

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

// Issue #70: SLA countdown/violation badge. sla_days is null when no
// SlaRule applies to this finding (group/severity or workspace default),
// render nothing in that case rather than a fabricated countdown.
// (#246) Whether this can be closed today, next to how bad it is.
//
// "unknown" renders nothing at all rather than a grey "unknown" chip. Most
// findings are unknown (every SAST and secrets finding carries no CVE to
// look up) so a chip on each one would be pure noise, and worse, it would
// read as a finding *about* the finding rather than an absence of data. The
// filter still exposes the state for anyone who wants to hunt for it.
function FixabilityBadge({ finding }: { finding: Finding }) {
  if (finding.fixability === "fixable") {
    return (
      <Badge
        variant="outline"
        title="An upgrade that resolves this is available"
        className="shrink-0 border-emerald-600/30 bg-emerald-600/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400"
      >
        Fix available
      </Badge>
    );
  }
  if (finding.fixability === "no_known_fix") {
    return (
      <Badge
        variant="outline"
        title="The advisory lists no fixed version yet"
        className="shrink-0 border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground"
      >
        No known fix
      </Badge>
    );
  }
  return null;
}

function SlaBadge({ finding }: { finding: Finding }) {
  const [now] = useState(() => Date.now());
  if (finding.sla_days === null || finding.sla_days === undefined) return null;

  const firstSeen = new Date(finding.first_seen).getTime();
  const deadline = firstSeen + finding.sla_days * 24 * 60 * 60 * 1000;
  // Captured once at mount rather than read during every render: the
  // countdown is day-granular, so re-reading the clock changes nothing a user
  // can see, and a render that depends on the current time is impure; two
  // renders of the same finding could disagree.
  const msLeft = deadline - now;
  const daysLeft = Math.ceil(Math.abs(msLeft) / (24 * 60 * 60 * 1000));

  if (finding.sla_violated) {
    return (
      <Badge
        variant="outline"
        title={`SLA: ${finding.sla_days}d to fix, first seen ${new Date(finding.first_seen).toLocaleDateString()}`}
        className="shrink-0 border-destructive/30 bg-destructive/10 px-2 py-0.5 text-xs font-medium text-destructive"
      >
        Overdue by {daysLeft}d
      </Badge>
    );
  }

  return (
    <Badge
      variant="outline"
      title={`SLA: ${finding.sla_days}d to fix`}
      className="shrink-0 border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground"
    >
      {daysLeft}d left
    </Badge>
  );
}

// GET /api/findings/{id}/enrichment (issue #71), real CVE/CWE/CVSS/fix-
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
    // No CVE on this finding (SAST/secrets finding); nothing to show here.
    return null;
  }

  const hasData =
    enrichment.cve_description || enrichment.cvss_score !== null || (enrichment.cwe_ids && enrichment.cwe_ids.length > 0) ||
    (enrichment.fix_versions && enrichment.fix_versions.length > 0) || (enrichment.references && enrichment.references.length > 0);

  return (
    <div className="mt-3 rounded-md border border-border bg-secondary/40 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Vulnerability Details</span>
        <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-muted-foreground" title="Sourced from public data (NVD/OSV.dev), no AI involved">
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
                href={safeHref(`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`)}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="mr-1 text-xs text-accent-strong underline"
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
                href={safeHref(url)}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="truncate text-xs text-accent-strong underline"
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

// Suggested-fix section inside FindingDetailDialog below. Fetches
// POST /api/findings/{id}/suggest-fix once when the dialog opens --
// generative but never writes anywhere by itself (app.core.autofix.
// suggest_fix never opens a PR; that's the separate, explicit "Raise PR"
// button here). `raiseResult`/`raiseError` are local to *this* generated
// patch: reopening the dialog or regenerating clears them, since a PR
// already opened for a since-replaced patch shouldn't look reusable.
function SuggestedFixSection({ finding }: { finding: Finding }) {
  const [data, setData] = useState<FindingSuggestFix | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [diffOpen, setDiffOpen] = useState(false);
  const [raising, setRaising] = useState(false);
  const [raiseResult, setRaiseResult] = useState<RaiseFixPrResult | null>(null);
  const [raiseError, setRaiseError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .suggestFix(finding.id)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "fix suggestion request failed");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  // User-triggered re-generation (the "regenerate" link below, or retrying
  // after an error) -- a click handler, not an effect, so setting loading
  // back to true synchronously here is fine.
  function generate() {
    setLoading(true);
    setError(null);
    setRaiseResult(null);
    setRaiseError(null);
    api
      .suggestFix(finding.id)
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "fix suggestion request failed"))
      .finally(() => setLoading(false));
  }

  function raisePr() {
    if (!data || !data.file_path || data.new_content === null || !data.ref || !data.strategy) return;
    setRaising(true);
    setRaiseError(null);
    api
      .raiseFixPr(finding.id, {
        file_path: data.file_path,
        new_content: data.new_content,
        ref: data.ref,
        strategy: data.strategy,
        explanation: data.explanation ?? "",
      })
      .then(setRaiseResult)
      .catch((e) => setRaiseError(e instanceof Error ? e.message : "raising the PR failed"))
      .finally(() => setRaising(false));
  }

  if (loading) {
    return <p className="text-xs text-muted-foreground">Generating a fix suggestion...</p>;
  }
  if (error) {
    return (
      <div className="flex items-center gap-2">
        <p className="text-xs text-destructive">{error}</p>
        <button onClick={generate} className="text-xs text-muted-foreground underline hover:text-foreground">
          retry
        </button>
      </div>
    );
  }
  if (!data) return null;

  const canRaisePr = Boolean(data.diff && data.file_path && data.new_content !== null && data.ref && data.strategy);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Suggested Fix</span>
        {data.strategy && (
          <Badge
            variant="outline"
            className="px-1.5 py-0 text-[10px] text-muted-foreground"
            title={data.strategy === "ai" ? "Generated by the configured AI provider" : "Deterministic dependency-version upgrade, no AI involved"}
          >
            {data.strategy === "ai" ? "AI-generated" : "no AI · dependency upgrade"}
          </Badge>
        )}
      </div>

      <p className="whitespace-pre-wrap text-sm text-foreground">{data.recommendation}</p>

      {!data.diff && (
        <p className="text-xs text-muted-foreground">
          No automated patch could be generated for this finding -- the recommendation above is the fix.
        </p>
      )}

      {data.diff && (
        <div>
          <button onClick={() => setDiffOpen((v) => !v)} className="text-xs text-muted-foreground underline hover:text-foreground">
            {diffOpen ? "Hide diff" : `Show diff${data.file_path ? ` (${data.file_path})` : ""}`}
          </button>
          {diffOpen && (
            <pre className="mt-1 max-h-64 overflow-auto rounded border border-border bg-secondary/40 p-2 text-[11px] leading-relaxed">
              {data.diff}
            </pre>
          )}
        </div>
      )}

      {canRaisePr && !raiseResult && (
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={raisePr} disabled={raising} className="self-start">
            <GitPullRequest className="h-3.5 w-3.5" />
            {raising ? "Raising PR..." : "Raise PR"}
          </Button>
          {raiseError && <p className="text-xs text-destructive">{raiseError}</p>}
        </div>
      )}

      {raiseResult && (
        <a
          href={safeHref(raiseResult.pr_url)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex w-fit items-center gap-1 rounded-md border border-success/30 bg-success/10 px-2 py-1 text-xs font-medium text-success"
        >
          <GitPullRequest className="h-3.5 w-3.5" />
          PR opened (#{raiseResult.pr_number})
        </a>
      )}

      <button onClick={generate} className="w-fit text-xs text-muted-foreground underline hover:text-foreground">
        regenerate
      </button>
    </div>
  );
}

// Clicking a finding's title opens this, replacing the old inline
// chevron-expand (which wasn't self-explanatory: nothing signaled that
// vulnerability detail *and* a fix suggestion lived behind an expand
// toggle). Everything about the finding -- description, no-AI CVE/CWE/OSV
// enrichment, and the suggested fix -- lives in one obviously-interactive
// popup instead.
function FindingDetailDialog({ finding, open, onClose }: { finding: Finding; open: boolean; onClose: () => void }) {
  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-dialog-title"
        className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-xl border border-border bg-card shadow-lg"
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
          <div className="flex min-w-0 flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity]}`}>
                {finding.severity}
              </Badge>
              <span id="finding-detail-dialog-title" className="truncate font-medium text-foreground">
                {finding.title}
              </span>
            </div>
            <span className="truncate text-xs text-muted-foreground">
              #{finding.id} · {finding.tool} · {finding.file_path}
              {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
            </span>
          </div>
          <button onClick={onClose} aria-label="Close" className="shrink-0 text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex flex-col gap-4 overflow-y-auto px-5 py-4">
          {finding.description && <p className="text-sm text-muted-foreground">{finding.description}</p>}
          <FindingEnrichmentPanel finding={finding} />
          <div className="rounded-md border border-border bg-secondary/40 p-3">
            <SuggestedFixSection finding={finding} />
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

export function FindingRow({
  finding,
  repoUrl,
  targetName,
  targetLabel,
  selectable = false,
  selected = false,
  onSelectChange,
}: {
  finding: Finding;
  repoUrl?: string;
  // Issue #117: target name/criticality label (Target.label: "Prod",
  // "Internal", "Dev", or a custom value), rendered as a CriticalityChip
  // next to the target it belongs to. Optional, callers without target
  // context (e.g. the onboarding wizard's finding preview) simply omit it
  // and no chip/target line renders.
  targetName?: string;
  targetLabel?: string;
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
    // `py-0` cancels the base Card's `py-6`. Without it every row carried
    // 48px of padding that no density token could reach, on top of
    // CardContent's own `--density-row-py`; which is why switching to
    // Compact only ever moved about 7% of the row height (#172). The token
    // now actually governs the row.
    <Card
      interactive
      className={`border-border bg-card border-l-4 py-0 ${SEVERITY_BORDER_COLOR[finding.severity]}`}
    >
      <CardContent className="px-4" style={{ paddingTop: "var(--density-row-py)", paddingBottom: "var(--density-row-py)" }}>
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
                {/* Vulnerability-type category (Code/SAST, Secret, OSS/SCA,
                    License, IaC, AI/ML, ...), same vocabulary Tool
                    Marketplace already shows. Deliberately one neutral style
                    for every category rather than a color per category --
                    this is a taxonomy tag, not a workflow status, so it does
                    not compete visually with the severity badge. */}
                {finding.category && (
                  <Badge
                    variant="outline"
                    className="shrink-0 px-2 py-0.5 text-xs font-medium text-muted-foreground"
                  >
                    {finding.category}
                  </Badge>
                )}
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
                  onClick={() => setDetailsOpen(true)}
                  className="flex min-w-0 items-center gap-1 truncate text-left text-sm font-medium text-foreground hover:underline"
                  title="View vulnerability details and suggested fix"
                >
                  <TruncateTooltip
                    text={finding.title}
                    subtext={`${finding.rule_id} · ${finding.tool}`}
                    className="font-medium text-foreground"
                  />
                </button>
              </div>
              {/* Issue #172: these two secondary lines each take a full line
                  in comfortable density and collapse onto one wrapping line
                  in compact; see .density-stack in globals.css. */}
              <div className="density-stack">
                <div className="mt-1 flex items-center gap-1 truncate text-xs text-muted-foreground">
                  <span className="truncate">
                    #{finding.id} · {finding.tool} · {finding.file_path}
                    {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
                  </span>
                  {repoUrl && finding.file_path && (
                    <a
                      href={safeHref(githubBlobUrl(repoUrl, finding.branch, finding.file_path, finding.line_start))}
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
                {(targetLabel || targetName) && (
                  <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
                    {targetLabel && <CriticalityChip label={targetLabel} />}
                    {targetName && <span className="truncate">{targetName}</span>}
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <FixabilityBadge finding={finding} />
            <SlaBadge finding={finding} />
            {/* Compact moves the Triage trigger up here, so the row doesn't
                need the full-width block below it at all (#172). */}
            {!open && (
              <button
                onClick={() => setOpen(true)}
                className="density-compact-only text-xs text-muted-foreground underline hover:text-foreground"
              >
                Triage
              </button>
            )}
            <div className="flex flex-col items-end gap-1">
              <RiskScore score={finding.priority_score} />
              <div className={`text-xs ${STATE_COLOR[finding.state] || "text-muted-foreground"}`}>{finding.state}</div>
            </div>
          </div>
        </div>

        <FindingDetailDialog finding={finding} open={detailsOpen} onClose={() => setDetailsOpen(false)} />

        <div className={open ? "mt-2" : "density-comfortable-only mt-2"}>
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
