"use client";

import { useEffect, useState } from "react";
import { ExternalLink, GitBranch, FileCode, CheckCircle2, Clock } from "lucide-react";
import { Finding, FindingEnrichment, api, githubBlobUrl } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Drawer } from "@/components/ui/drawer";
import { SeverityChip } from "@/components/ui/severity-chip";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AlertBanner } from "@/components/ui/alert-banner";
import { Skeleton } from "@/components/ui/skeleton";
import { EPSS_BADGE_COLOR, EPSS_NOTABLE_THRESHOLD, KEV_BADGE_COLOR, STATE_COLOR } from "@/lib/severity";


export interface FindingDetailDrawerProps {
  finding: Finding | null;
  repoUrl?: string;
  targetName?: string;
  onClose: () => void;
  onTriageSuccess?: () => void;
}

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

function FindingDetailDrawerContent({
  finding,
  repoUrl,
  targetName,
  onClose,
  onTriageSuccess,
}: {
  finding: Finding;
  repoUrl?: string;
  targetName?: string;
  onClose: () => void;
  onTriageSuccess?: () => void;
}) {
  const [enrichment, setEnrichment] = useState<FindingEnrichment | null>(null);
  const [loadingEnrichment, setLoadingEnrichment] = useState(true);
  const [enrichmentError, setEnrichmentError] = useState<string | null>(null);

  const [triageState, setTriageState] = useState(finding.state);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [triageSuccess, setTriageSuccess] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .findingEnrichment(finding.id)
      .then((data) => {
        if (!cancelled) setEnrichment(data);
      })
      .catch((e) => {
        if (!cancelled) setEnrichmentError(e instanceof Error ? e.message : "Enrichment lookup failed");
      })
      .finally(() => {
        if (!cancelled) setLoadingEnrichment(false);
      });

    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  async function handleTriage(toState: string) {
    setSubmitting(true);
    setTriageError(null);
    try {
      await api.triage(finding.id, toState, reason);
      setTriageState(toState);
      setTriageSuccess(true);
      onTriageSuccess?.();
    } catch (e) {
      setTriageError(e instanceof Error ? e.message : "Triage failed");
    } finally {
      setSubmitting(false);
    }
  }

  const blobUrl = repoUrl
    ? githubBlobUrl(repoUrl, finding.branch || "main", finding.file_path, finding.line_start)
    : null;

  return (
    <Drawer
      open={true}
      onClose={onClose}
      size="xl"
      title={
        <div className="flex items-center gap-2.5">
          <SeverityChip severity={finding.severity} size="md" />
          <span className="truncate font-semibold">{finding.title}</span>
        </div>
      }
      description={
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-code text-foreground">{finding.rule_id}</span>
          <span className="text-meta">·</span>
          <span className="text-body-sm text-muted-foreground">{finding.tool}</span>
          {finding.kev_listed && (
            <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${KEV_BADGE_COLOR}`}>
              CISA KEV
            </Badge>
          )}
          {!finding.kev_listed && finding.epss_score !== null && finding.epss_score !== undefined && finding.epss_score > EPSS_NOTABLE_THRESHOLD && (
            <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold ${EPSS_BADGE_COLOR}`}>
              EPSS {(finding.epss_score * 100).toFixed(0)}%
            </Badge>
          )}

        </div>
      }
      footer={
        <div className="flex w-full items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Current State:</span>
            <Badge variant="outline" className={`text-xs font-medium capitalize ${STATE_COLOR[triageState] || ""}`}>
              {triageState}
            </Badge>
          </div>
          <Button variant="outline" size="sm" onClick={onClose}>
            Done
          </Button>
        </div>
      }
    >
      {/* 1. High-Value Status & SLA Metrics Banner */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-lg border border-border bg-secondary/30 p-3">
        <div>
          <div className="text-meta uppercase tracking-wider text-muted-foreground">Technical Severity</div>
          <div className="mt-1 font-semibold text-foreground">{finding.severity}</div>
        </div>
        <div>
          <div className="text-meta uppercase tracking-wider text-muted-foreground">Contextual Risk</div>
          <div className="mt-1 font-mono font-bold text-foreground tabular-nums">
            {finding.priority_score} <span className="text-xs text-muted-foreground">/ 1000</span>
          </div>
        </div>
        <div>
          <div className="text-meta uppercase tracking-wider text-muted-foreground">Workflow Status</div>
          <div className="mt-1 font-medium capitalize text-foreground">{triageState}</div>
        </div>
        <div>
          <div className="text-meta uppercase tracking-wider text-muted-foreground">SLA Window</div>
          <div className="mt-1 flex items-center gap-1 font-mono text-xs tabular-nums">
            <Clock className="h-3 w-3 text-muted-foreground" />
            {finding.sla_days ? (
              finding.sla_violated ? (
                <span className="font-semibold text-destructive">Overdue ({finding.sla_days}d SLA)</span>
              ) : (
                <span className="text-muted-foreground">{finding.sla_days}d SLA</span>
              )
            ) : (
              <span className="text-muted-foreground">No SLA</span>
            )}
          </div>
        </div>
      </div>

      {/* 2. Affected Asset Coordinates */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Affected Asset & Location
        </h3>
        <div className="rounded-lg border border-border bg-background p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-foreground font-medium">
              <GitBranch className="h-4 w-4 text-primary shrink-0" />
              <span>{targetName || `Target #${finding.target_id}`}</span>
            </div>
            {repoUrl && (
              <a
                href={safeHref(repoUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-accent-strong hover:underline"
              >
                Repo <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>

          <div className="flex items-center justify-between text-xs border-t border-border/60 pt-2">
            <div className="flex items-center gap-2 font-mono text-muted-foreground truncate">
              <FileCode className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <span className="truncate">
                {finding.file_path}
                {finding.line_start ? `:${finding.line_start}` : ""}
              </span>
            </div>
            {blobUrl && (
              <a
                href={safeHref(blobUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-accent-strong hover:underline shrink-0 ml-2"
              >
                Source <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        </div>
      </div>

      {/* 3. Vulnerability Description & Threat Intelligence */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Vulnerability & Threat Context
        </h3>
        <div className="rounded-lg border border-border bg-background p-4 space-y-3">
          {loadingEnrichment && (
            <div className="space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </div>
          )}

          {enrichmentError && (
            <AlertBanner tone="warning" title="Enrichment unavailable">
              {enrichmentError}
            </AlertBanner>
          )}

          {!loadingEnrichment && enrichment && (
            <>
              {enrichment.cve_description && (
                <p className="text-body-sm text-foreground leading-relaxed">
                  {enrichment.cve_description}
                </p>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 border-t border-border pt-3">
                {enrichment.cvss_score !== null && enrichment.cvss_score !== undefined && (
                  <div>
                    <span className="text-xs font-medium text-foreground">CVSS Score: </span>
                    <span className="font-mono text-xs font-bold text-foreground tabular-nums">
                      {enrichment.cvss_score.toFixed(1)}
                    </span>
                    {enrichment.cvss_vector && (
                      <div className="font-mono text-[10px] text-muted-foreground mt-0.5 truncate">
                        {enrichment.cvss_vector}
                      </div>
                    )}
                  </div>
                )}

                {enrichment.cwe_ids && enrichment.cwe_ids.length > 0 && (
                  <div>
                    <span className="text-xs font-medium text-foreground">CWE Classification: </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {enrichment.cwe_ids.map((cwe) => (
                        <a
                          key={cwe}
                          href={safeHref(`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-xs text-accent-strong underline mr-1.5"
                        >
                          {cwe}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Fix Versions & Upgrades */}
              {enrichment.fix_versions && enrichment.fix_versions.length > 0 && (
                <div className="border-t border-border pt-3">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-chart-5 mb-1">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    <span>Fixed in Version:</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {enrichment.fix_versions.map((ver, idx) => (
                      <span
                        key={idx}
                        className="rounded border border-chart-5/30 bg-chart-5/10 px-2 py-0.5 font-mono text-xs font-medium text-chart-5"
                      >
                        {ver.package ? `${ver.package}@` : ""}{ver.fixed}
                      </span>
                    ))}
                  </div>
                </div>
              )}

            </>
          )}

          {!loadingEnrichment && !enrichment && (
            <p className="text-body-sm text-muted-foreground">
              SAST / code-rule finding detected by {finding.tool}. No external CVE lookup required.
            </p>
          )}
        </div>
      </div>

      {/* 4. Interactive Quick Triage Workflow */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Workflow Triage & State Transition
        </h3>
        <div className="rounded-lg border border-border bg-background p-4 space-y-3">
          <p className="text-xs text-muted-foreground">
            Update finding state with an audit justification for compliance logs.
          </p>

          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              placeholder="Reason / justification (e.g. mitigated by WAF rule)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="flex-1 text-xs"
            />
          </div>

          <div className="flex flex-wrap gap-2 pt-1">
            {TRIAGE_STATES.map((state) => (
              <Button
                key={state}
                size="sm"
                variant={triageState === state ? "default" : "outline"}
                disabled={submitting || triageState === state}
                onClick={() => handleTriage(state)}
                className="text-xs"
              >
                {submitting ? "Updating..." : `Set to ${state}`}
              </Button>
            ))}
          </div>

          {triageSuccess && (
            <AlertBanner tone="positive" title="State Updated">
              Finding status changed to <strong>{triageState}</strong>.
            </AlertBanner>
          )}

          {triageError && (
            <AlertBanner tone="critical" title="Triage Failed">
              {triageError}
            </AlertBanner>
          )}
        </div>
      </div>
    </Drawer>
  );
}

export function FindingDetailDrawer(props: FindingDetailDrawerProps) {
  const { finding, ...rest } = props;
  if (!finding) return null;
  return <FindingDetailDrawerContent key={finding.id} finding={finding} {...rest} />;
}
