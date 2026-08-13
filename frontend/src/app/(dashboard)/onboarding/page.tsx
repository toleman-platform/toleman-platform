"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, Target, Finding } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { FindingRow } from "@/components/finding-row";
import { CheckCircle2, XCircle, Github, ArrowRight } from "lucide-react";

const STEPS = [
  { n: 1, label: "Connect a repo" },
  { n: 2, label: "Run first scan" },
  { n: 3, label: "See a finding" },
  { n: 4, label: "You're all set" },
];

const LABELS = ["Prod", "Dev", "Internal", "Public"];
const WEIGHT_BY_LABEL: Record<string, number> = { Prod: 5, Public: 4, Internal: 3, Dev: 2 };

export default function OnboardingPage() {
  const router = useRouter();

  const [step, setStep] = useState(1);
  const [loadingInitial, setLoadingInitial] = useState(true);

  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);

  // Step 1 - GitHub connect
  const [githubStatus, setGithubStatus] = useState<{
    app_configured: boolean;
    app_slug: string | null;
    installed: boolean;
    account_login: string | null;
    webhook_secret_set: boolean;
  } | null>(null);
  const [org, setOrg] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  // Step 1 - manual target fallback
  const [manualName, setManualName] = useState("");
  const [manualRepoUrl, setManualRepoUrl] = useState("");
  const [manualBranch, setManualBranch] = useState("main");
  const [manualLabel, setManualLabel] = useState("Dev");
  const [manualSubmitting, setManualSubmitting] = useState(false);
  const [manualError, setManualError] = useState<string | null>(null);
  const [showManualForm, setShowManualForm] = useState(false);

  // Step 2 - scan
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<{ scan_id: number; findings_count: number } | null>(null);

  // Step 3 - findings
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);

  async function loadTargetsAndStatus() {
    const [ts, gh] = await Promise.all([
      api.targets().catch(() => []),
      api.githubAppStatus().catch(() => null),
    ]);
    setTargets(ts);
    setGithubStatus(gh);
    if (ts.length > 0) {
      setSelectedTargetId((prev) => prev ?? ts[0].id);
      setStep((s) => (s < 2 ? 2 : s));
    }
    return ts;
  }

  useEffect(() => {
    loadTargetsAndStatus().finally(() => setLoadingInitial(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function connectGithub() {
    setConnecting(true);
    setConnectError(null);
    try {
      const { manifest, post_url } = await api.githubAppManifestData(org || undefined);
      const form = document.createElement("form");
      form.action = post_url;
      form.method = "post";
      form.style.display = "none";
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "manifest";
      input.value = JSON.stringify(manifest);
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    } catch (e) {
      setConnectError(e instanceof Error ? e.message : "failed to start GitHub connect flow");
      setConnecting(false);
    }
  }

  async function syncGithub() {
    setSyncing(true);
    try {
      await api.githubAppSync();
      const ts = await loadTargetsAndStatus();
      if (ts.length > 0) setStep(2);
    } finally {
      setSyncing(false);
    }
  }

  async function submitManualTarget(e: React.FormEvent) {
    e.preventDefault();
    setManualSubmitting(true);
    setManualError(null);
    try {
      const created = await api.createTarget({
        workspace_id: 1,
        name: manualName,
        repo_url: manualRepoUrl,
        default_branch: manualBranch,
        label: manualLabel,
        criticality_weight: WEIGHT_BY_LABEL[manualLabel] ?? 1,
      });
      setTargets((prev) => [...prev, created]);
      setSelectedTargetId(created.id);
      setManualName("");
      setManualRepoUrl("");
      setStep(2);
    } catch (err) {
      setManualError(err instanceof Error ? err.message : "failed to create target");
    } finally {
      setManualSubmitting(false);
    }
  }

  async function runFirstScan(targetId: number) {
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    try {
      // POST /api/scans/run now dispatches a Celery task and returns
      // immediately with status: "running" (#59) instead of blocking until
      // the clone+scan finishes -- poll GET /api/scans/{scan_id} until it's
      // done.
      const res = await api.runScan(targetId, "semgrep");
      if ("error" in res) {
        setScanError(res.error);
        setScanning(false);
        return;
      }

      const scanId = res.scan_id;
      pollUntilSettled(
        async () => {
          const scan = await api.getScan(scanId);
          if ("error" in scan) return { status: "failed" as const, message: scan.error };
          return { status: scan.status, findings_count: scan.findings_count };
        },
        async (scan) => {
          if (scan.status === "completed") {
            setScanResult({ scan_id: scanId, findings_count: scan.findings_count });
            setFindingsLoading(true);
            const result = await api
              .findings({ target_id: targetId, page_size: 5 })
              .catch(() => ({ items: [], total: 0 }));
            setFindings(result.items);
            setFindingsLoading(false);
            setStep(3);
            setScanning(false);
          } else if (scan.status === "failed") {
            setScanError(scan.message ?? "scan failed");
            setScanning(false);
          }
        },
        {
          onError: (err) => {
            setScanError(err instanceof Error ? err.message : "scan failed");
            setScanning(false);
          },
        },
      );
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "scan failed");
      setScanning(false);
    }
  }

  const selectedTarget = targets.find((t) => t.id === selectedTargetId) ?? null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Get started with OSP</h1>
          <p className="text-sm text-muted-foreground">
            Connect a repo, run a scan, and see what OSP finds — in under a minute.
          </p>
        </div>
        <Link href="/" className="text-xs text-muted-foreground underline hover:text-foreground">
          Skip onboarding
        </Link>
      </div>

      <div className="flex items-center gap-2">
        {STEPS.map((s, i) => (
          <div key={s.n} className="flex items-center gap-2">
            <Badge
              variant={step >= s.n ? "default" : "outline"}
              className={step >= s.n ? "" : "text-muted-foreground"}
            >
              {step > s.n ? <CheckCircle2 className="h-3 w-3" /> : s.n}
              <span className="ml-1">{s.label}</span>
            </Badge>
            {i < STEPS.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground" />}
          </div>
        ))}
      </div>

      {loadingInitial && (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col gap-2 px-4 py-4">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-9 w-40" />
          </CardContent>
        </Card>
      )}

      {!loadingInitial && step === 1 && (
        <div className="flex flex-col gap-4">
          <Card className="border-border bg-card">
            <CardContent className="flex flex-col gap-4 px-4 py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Github className="h-5 w-5" />
                </div>
                <div>
                  <div className="font-medium text-foreground">Connect via GitHub</div>
                  <div className="text-xs text-muted-foreground">
                    Install the OSP GitHub App to sync and auto-discover repos
                  </div>
                </div>
              </div>

              {githubStatus === null && (
                <div className="flex flex-col gap-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-9 w-40" />
                </div>
              )}

              {githubStatus && !githubStatus.app_configured && (
                <div className="flex flex-col gap-2">
                  <p className="text-xs text-muted-foreground">
                    Leave blank to install on your personal account, or enter an org name to install there instead.
                  </p>
                  <div className="flex gap-2">
                    <Input
                      className="bg-secondary"
                      placeholder="Organization (optional)"
                      value={org}
                      onChange={(e) => setOrg(e.target.value)}
                    />
                    <Button onClick={connectGithub} disabled={connecting} className="shrink-0">
                      {connecting ? "Redirecting..." : "Connect GitHub"}
                    </Button>
                  </div>
                  {connectError && <p className="text-xs text-destructive">{connectError}</p>}
                </div>
              )}

              {githubStatus && githubStatus.app_configured && !githubStatus.installed && (
                <div className="flex flex-col gap-2">
                  <p className="text-sm text-muted-foreground">
                    App <code className="text-foreground">{githubStatus.app_slug}</code> was created. Finish
                    installing it on your account or org:
                  </p>
                  <a
                    href={`https://github.com/apps/${githubStatus.app_slug}/installations/new`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <Button>Install App</Button>
                  </a>
                </div>
              )}

              {githubStatus && githubStatus.installed && (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2 text-sm text-chart-5">
                    <CheckCircle2 className="h-4 w-4" />
                    Connected as {githubStatus.account_login}
                  </div>
                  <Button onClick={syncGithub} disabled={syncing} variant="outline" className="self-start">
                    {syncing ? "Syncing..." : "Sync Repos Now"}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs text-muted-foreground">or</span>
            <div className="h-px flex-1 bg-border" />
          </div>

          {!showManualForm ? (
            <Button variant="outline" onClick={() => setShowManualForm(true)} className="self-start">
              Add a repo manually instead
            </Button>
          ) : (
            <Card className="border-border bg-card">
              <CardContent className="px-4 py-4">
                <form onSubmit={submitManualTarget} className="flex flex-col gap-3">
                  <div className="grid grid-cols-2 gap-3">
                    <Input
                      className="bg-secondary text-sm"
                      placeholder="Target name (e.g. govwa)"
                      value={manualName}
                      onChange={(e) => setManualName(e.target.value)}
                      required
                    />
                    <Input
                      className="bg-secondary text-sm"
                      placeholder="Repo URL (https://github.com/org/repo)"
                      value={manualRepoUrl}
                      onChange={(e) => setManualRepoUrl(e.target.value)}
                      required
                    />
                    <Input
                      className="bg-secondary text-sm"
                      placeholder="Default branch"
                      value={manualBranch}
                      onChange={(e) => setManualBranch(e.target.value)}
                    />
                    <select
                      className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                      value={manualLabel}
                      onChange={(e) => setManualLabel(e.target.value)}
                    >
                      {LABELS.map((l) => (
                        <option key={l} value={l}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </div>
                  {manualError && <p className="text-xs text-destructive">{manualError}</p>}
                  <Button type="submit" disabled={manualSubmitting} className="self-start">
                    {manualSubmitting ? "Adding..." : "Add Target"}
                  </Button>
                </form>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {!loadingInitial && step === 2 && (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            {targets.length} target{targets.length === 1 ? "" : "s"} connected. Pick one to run your first scan
            (semgrep — fast static analysis, works on most repos).
          </p>
          <div className="flex flex-col gap-3">
            {targets.map((t) => (
              <Card
                key={t.id}
                className={`border-border bg-card ${selectedTargetId === t.id ? "border-primary/50" : ""}`}
              >
                <CardContent className="flex items-center justify-between px-4 py-3">
                  <div>
                    <div className="font-medium text-foreground">{t.name}</div>
                    <div className="text-xs text-muted-foreground">{t.repo_url}</div>
                  </div>
                  <Button
                    size="sm"
                    disabled={scanning}
                    onClick={() => {
                      setSelectedTargetId(t.id);
                      runFirstScan(t.id);
                    }}
                  >
                    {scanning && selectedTargetId === t.id ? "Scanning… this can take a while" : "Run first scan"}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
          {scanError && <p className="text-xs text-destructive">{scanError}</p>}
        </div>
      )}

      {!loadingInitial && step === 3 && (
        <div className="flex flex-col gap-4">
          {scanResult && (
            <p className="text-sm text-muted-foreground">
              Scan complete on <span className="text-foreground">{selectedTarget?.name}</span> —{" "}
              {scanResult.findings_count} finding{scanResult.findings_count === 1 ? "" : "s"} ingested.
            </p>
          )}

          {findingsLoading && (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          )}

          {!findingsLoading && findings && findings.length === 0 && (
            <Card className="border-border bg-card">
              <CardContent className="flex items-center gap-3 px-4 py-4">
                <CheckCircle2 className="h-5 w-5 text-chart-5" />
                <div>
                  <div className="text-sm font-medium text-foreground">No findings — this repo looks clean</div>
                  <div className="text-xs text-muted-foreground">
                    Nothing to show yet, but you can still browse the{" "}
                    <Link href="/findings" className="text-primary underline">
                      Findings
                    </Link>{" "}
                    page any time.
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {!findingsLoading && findings && findings.length > 0 && (
            <div className="flex flex-col gap-3">
              {findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}

          <Button onClick={() => setStep(4)} className="self-start">
            Continue
          </Button>
        </div>
      )}

      {!loadingInitial && step === 4 && (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col items-start gap-4 px-4 py-6">
            <div className="flex items-center gap-2 text-lg font-semibold text-foreground">
              <CheckCircle2 className="h-5 w-5 text-chart-5" />
              You&apos;re all set
            </div>
            <p className="text-sm text-muted-foreground">
              Your repo is connected and OSP has scanned it at least once. From here you can explore the full
              dashboard, browse all findings, or connect more repos any time from Settings.
            </p>
            <div className="flex gap-3">
              <Button onClick={() => router.push("/")}>Go to Dashboard</Button>
              <Button variant="outline" onClick={() => router.push("/findings")}>
                Browse Findings
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {!loadingInitial && step !== 1 && (
        <button
          onClick={() => setStep(1)}
          className="self-start text-xs text-muted-foreground underline hover:text-foreground"
        >
          Back to connect step
        </button>
      )}
    </div>
  );
}
