"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, GitHubAppInstallation } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWriteAction } from "@/hooks/use-write-action";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { AsyncContent } from "@/components/ui/async-content";
import { AlertBanner } from "@/components/ui/alert-banner";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Github, CheckCircle2, XCircle, Trash2, AlertTriangle } from "lucide-react";

type GithubAppStatus = {
  apps: GitHubAppInstallation[];
  app_configured: boolean;
  app_slug: string | null;
  installed: boolean;
  account_login: string | null;
  webhook_secret_set: boolean;
  // (#355) Not about any App in `apps` -- about the one being created.
  // False means GitHub will reject the manifest outright, so "Connect
  // GitHub" cannot succeed until PUBLIC_API_URL (echoed as
  // public_api_url) is publicly reachable.
  webhook_reachable: boolean;
  public_api_url: string;
};

/**
 * The host out of PUBLIC_API_URL, or "" when the value has none.
 *
 * Mirrors the backend's `_webhook_hostname`, and the mirroring is the whole
 * point: the two parsers disagreeing is how the UI ends up making confident
 * statements about a configuration the backend judged differently. Three
 * places they drift, all normalised here:
 *
 *   - `new URL().hostname` brackets an IPv6 literal (`"[::1]"`) where
 *     Python's `urlparse().hostname` does not.
 *   - it keeps the trailing dot of an FQDN (`backend.`) that
 *     `_webhook_hostname` strips.
 *   - a base URL would let a schemeless value containing a mid-string `//`
 *     ("foo//bar") resolve as a *path* against that base, handing back the
 *     base's own hostname as if it were the operator's. So: no base, and
 *     the three shapes are separated explicitly instead. A protocol-relative
 *     value ("//localhost:8000") wears its host openly and only needs a
 *     scheme; one with no `//` at all gets the same scheme-prepending
 *     allowance the backend makes; anything else is parsed as written.
 *
 * Never throws; an unparseable value is "".
 */
function hostOf(publicApiUrl: string): string {
  const candidate = publicApiUrl.trim();
  if (!candidate) return "";
  let absolute = candidate;
  if (candidate.startsWith("//")) absolute = `http:${candidate}`;
  else if (!candidate.includes("//")) absolute = `http://${candidate}`;
  try {
    const { hostname } = new URL(absolute);
    return hostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
  } catch {
    return "";
  }
}

/**
 * PUBLIC_API_URL is empty, or not a URL with a host in it at all.
 *
 * The backend reports this unreachable (rightly -- there is nothing for
 * GitHub to deliver to), which means the blocking banner renders; this is
 * what stops that banner claiming "is a localhost address" next to an empty
 * value. Unset and wrong are different problems with different fixes.
 */
function hasNoUsableHost(publicApiUrl: string): boolean {
  return hostOf(publicApiUrl) === "";
}

/**
 * The advisory tier under `webhook_reachable` (#355 review).
 *
 * The backend says False only for what is certain -- a host that is not
 * globally routable, or no host at all -- because False disables the
 * Connect button and there is no override. A single-label host with no dot
 * in it (`backend`, a Compose service name) is *almost* certainly
 * unreachable from GitHub too, and "almost" is the line: this warns and
 * lets the operator click anyway, which is the override the backend
 * predicate cannot offer.
 *
 * Note this is about a dotless *name*. IP literals are excluded entirely,
 * in both directions: a LAN address (`192.168.1.50`) has dots and would
 * slip past a dot test anyway, and an IPv6 literal (`2606:4700::1111`) has
 * none and would wrongly trip it. The backend has already had the final
 * word on every IP literal -- it blocks the ones that are not globally
 * routable and allows the rest -- so telling an operator that a public v6
 * address "resolves only inside your own network" would be a confidently
 * false statement about a valid configuration.
 */
function hostIsDotless(publicApiUrl: string): boolean {
  const hostname = hostOf(publicApiUrl);
  if (!hostname) return false;
  // A colon survives bracket-stripping only for an IPv6 literal; no
  // hostname can contain one.
  if (hostname.includes(":")) return false;
  return !hostname.includes(".");
}

export function ConnectGithubCard() {
  const router = useRouter();
  // (#355 review) One state machine for the status read, rather than a
  // hand-rolled `status`/`error` pair: that version left `status` null on a
  // failed read, so the card rendered a skeleton forever next to a disabled
  // button and a one-line error, with no way to retry. AsyncContent below
  // renders loading/error/loaded once, correctly, with a Try again action
  // (issue #210).
  const statusState = useAsyncData<GithubAppStatus>(() => api.githubAppStatus());
  const [org, setOrg] = useState("");
  // M24: success and failure used to share one `syncResult: string | null`,
  // rendered through the same `text-xs text-muted-foreground` paragraph --
  // "sync failed" got the identical neutral treatment as "3 new repo(s)
  // added as targets", so a sync that failed read, at a glance, exactly like
  // one that worked. `useWriteAction` keeps the failure in its own `error`
  // slot instead of a string this component would have to re-inspect to
  // classify, and `syncCreated` (a count, not a message) is only ever set on
  // the success path, so `AlertBanner`'s tone -- critical vs. positive, its
  // own icon and color -- is picked from *which* state produced it rather
  // than sniffed out of the string afterward. `null` means "no result to
  // show yet"; `0` is a real, renderable success ("0 new repos" -- nothing
  // new since the last sync -- is not the same as no attempt having run).
  const syncAction = useWriteAction("Sync failed");
  const [syncCreated, setSyncCreated] = useState<number | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [webhookSecrets, setWebhookSecrets] = useState<Record<number, string>>({});
  const [savingSecretFor, setSavingSecretFor] = useState<number | null>(null);
  // Deleting a registered App drops its private key/client secret and every
  // installation row under it -- same destructive-confirmation pattern as
  // workspace-roles.tsx's role removal, not a bare button with no warning.
  const [pendingDelete, setPendingDelete] = useState<GitHubAppInstallation | null>(null);
  const [deleting, setDeleting] = useState(false);

  function refresh() {
    // `error` holds the last *action* failure (delete, connect). Clearing it
    // here means a repaint after a successful action doesn't leave "failed
    // to delete GitHub App" sitting under a card that now shows the delete
    // worked. Load failures are AsyncContent's to render, not this line's.
    setError(null);
    statusState.refetch();
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.deleteGithubApp(pendingDelete.id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete GitHub App");
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }

  async function connect() {
    setConnecting(true);
    setError(null);
    try {
      const { manifest, post_url } = await api.githubAppManifestData(org || undefined);
      // Built and submitted imperatively (not via React state -> JSX -> ref) so
      // there's no render-timing race between setting the value and submitting.
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
      setError(e instanceof Error ? e.message : "failed to start GitHub connect flow");
      setConnecting(false);
    }
  }

  async function sync() {
    setSyncCreated(null);
    await syncAction.run(async () => {
      const res = await api.githubAppSync();
      setSyncCreated(res.created);
      router.refresh();
    });
  }

  async function saveWebhookSecret(configId: number) {
    const value = (webhookSecrets[configId] || "").trim();
    if (!value) return;
    setSavingSecretFor(configId);
    try {
      await api.updateWebhookSecret(value, configId);
      setWebhookSecrets((prev) => ({ ...prev, [configId]: "" }));
      refresh();
    } finally {
      setSavingSecretFor(null);
    }
  }

  return (
    <>
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
            <Github className="h-5 w-5" />
          </div>
          <div>
            <div className="font-medium text-foreground">GitHub</div>
            <div className="text-xs text-muted-foreground">
              Install one or more Toleman GitHub Apps to sync and auto-discover repos
            </div>
          </div>
        </div>

        <AsyncContent
          state={statusState}
          itemNoun="GitHub Apps"
          errorTitle="Couldn't load GitHub App status"
          // An empty `apps` list is not an empty state here: the card's whole
          // job in that case is to render the connect flow below.
          isEmpty={() => false}
          loadingFallback={
            <div className="flex flex-col gap-2">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-9 w-40" />
            </div>
          }
        >
          {(status) => (
            <div className="flex flex-col gap-4">
              {status.apps.length > 0 && (
                <div className="flex flex-col gap-3">
                  {status.apps.map((appEntry) => (
                    <div key={appEntry.id} className="rounded-md border border-border p-3">
                      <div className="flex items-center justify-between">
                        <div className="text-sm font-medium text-foreground">
                          <code>{appEntry.app_slug}</code>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button asChild size="sm" variant="outline">
                            <a href={safeHref(`https://github.com/apps/${appEntry.app_slug}/installations/new`)} target="_blank" rel="noreferrer">
                              Add installation
                            </a>
                          </Button>
                          {/* GitHub Apps have no API to change permissions or
                              webhook event subscriptions -- only the App's own
                              settings page can. A "Manage on GitHub" link is the
                              honest affordance here; an in-app edit form would
                              imply Toleman can do this itself, which it can't.
                              manage_url is server-computed (org- vs personal-owned
                              Apps live under different URL shapes; guessing 404s). */}
                          <Button asChild size="sm" variant="outline">
                            <a href={safeHref(appEntry.manage_url)} target="_blank" rel="noreferrer">
                              Manage on GitHub
                            </a>
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-destructive hover:text-destructive"
                            onClick={() => setPendingDelete(appEntry)}
                            aria-label={`Remove GitHub App ${appEntry.app_slug} from Toleman`}
                            title={`Remove GitHub App ${appEntry.app_slug} from Toleman`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>

                      {appEntry.installations.length === 0 ? (
                        <p className="mt-1 text-xs text-muted-foreground">
                          App created but not installed on any account/org yet.
                        </p>
                      ) : (
                        <div className="mt-1 flex flex-col gap-1">
                          {appEntry.installations.map((inst) => (
                            <div key={inst.installation_id} className="flex items-center gap-2 text-xs text-chart-5">
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              <span className="text-muted-foreground">
                                Connected as {inst.account_login} ({inst.account_type})
                              </span>
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="mt-2 flex flex-col gap-2 border-t border-border pt-2">
                        {/* Worst blocker first. An unreachable host beats a
                            missing secret, because a delivery that never
                            arrives is never checked against a secret -- and
                            the old two-way version claimed "real-time PR
                            scanning active" on the strength of the secret
                            alone, which reads as a clean bill of health for an
                            App whose webhook is dead (#355 review). */}
                        <div className="flex items-center gap-2 text-xs">
                          {!status.webhook_reachable ? (
                            <>
                              <XCircle className="h-3.5 w-3.5 text-destructive" />
                              <span className="text-muted-foreground">
                                Webhook deliveries to this App cannot arrive:{" "}
                                {hasNoUsableHost(status.public_api_url) ? (
                                  <>
                                    <code>PUBLIC_API_URL</code> has no usable address in it
                                  </>
                                ) : (
                                  <>
                                    <code>PUBLIC_API_URL</code> is <code>{status.public_api_url}</code>
                                  </>
                                )}
                              </span>
                            </>
                          ) : appEntry.webhook_secret_set ? (
                            <>
                              <CheckCircle2 className="h-3.5 w-3.5 text-chart-5" />
                              <span className="text-muted-foreground">
                                Webhook secret set, real-time PR scanning active if this App&apos;s webhook is configured
                              </span>
                            </>
                          ) : (
                            <>
                              <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="text-muted-foreground">
                                No webhook secret set, PRs from this App only scan on-demand (PR History page)
                              </span>
                            </>
                          )}
                        </div>
                        {/* The degraded mode that really does exist, and is a
                            different problem from the pre-create banner below:
                            this App was created while PUBLIC_API_URL was
                            public, and the address has since gone back to
                            localhost (a tunnel died, a .env was reverted). The
                            App is real, its deliveries are not. */}
                        {!status.webhook_reachable && (
                          <p className="text-xs text-muted-foreground">
                            This App already exists, so nothing is rejected here -- GitHub just has nowhere to
                            deliver to. Its webhook URL was fixed when it was created and no API can change it,
                            so point <code>PUBLIC_API_URL</code> back at a publicly reachable address (and
                            restart <code>backend</code> and <code>celery-worker</code>); if that address is
                            different from the one this App was created with, edit the App&apos;s webhook URL by
                            hand under &quot;Manage on GitHub&quot; above to match. Until then PRs only scan on
                            demand from the PR History page, and a required status check that nothing triggers
                            blocks every PR.
                          </p>
                        )}
                        <div className="flex gap-2">
                          <Input
                            type="password"
                            autoComplete="off"
                            spellCheck={false}
                            aria-label={`Webhook secret for ${appEntry.app_slug}`}
                            className="bg-secondary"
                            placeholder="Webhook secret (must match this App's GitHub settings)"
                            value={webhookSecrets[appEntry.id] || ""}
                            onChange={(e) => setWebhookSecrets((prev) => ({ ...prev, [appEntry.id]: e.target.value }))}
                          />
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => saveWebhookSecret(appEntry.id)}
                            disabled={savingSecretFor === appEntry.id || !(webhookSecrets[appEntry.id] || "").trim()}
                            className="shrink-0"
                          >
                            {savingSecretFor === appEntry.id ? "Saving..." : "Save"}
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}

                  <Button onClick={sync} disabled={syncAction.submitting} variant="outline" className="self-start">
                    {syncAction.submitting ? "Syncing..." : "Sync Repos Now"}
                  </Button>
                  {syncAction.error ? (
                    <AlertBanner tone="critical" title="Sync failed">
                      {syncAction.error}
                    </AlertBanner>
                  ) : (
                    syncCreated !== null && (
                      <AlertBanner tone="positive">{syncCreated} new repo(s) added as targets</AlertBanner>
                    )
                  )}
                </div>
              )}

              <div className="flex flex-col gap-2 border-t border-border pt-3">
                {/* (#355) Rendered before the create action, not next to
                    existing Apps, because the only install this can happen on
                    is one with no Apps at all: a default local install, where
                    the operator previously got no warning here and GitHub's
                    rejection page instead. The button below is disabled on the
                    same condition, so the failure is caught here rather than on
                    github.com. */}
                {!status.webhook_reachable && (
                  <div className="flex gap-2 rounded-md border border-border bg-secondary p-3">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                    <div className="flex flex-col gap-2 text-xs text-muted-foreground">
                      {/* Unset and wrong are different problems: the second
                          branch's "resolves only inside this network" is a
                          lie about an empty value, and the old copy named
                          localhost specifically, which is wrong for the LAN
                          addresses the backend also refuses. */}
                      {hasNoUsableHost(status.public_api_url) ? (
                        <>
                          <p className="font-medium text-foreground">
                            GitHub will reject a new App while <code>PUBLIC_API_URL</code> has no usable address
                            in it.
                          </p>
                          <p>
                            <code>PUBLIC_API_URL</code> is empty, or not a URL with a host Toleman can read, so
                            the App manifest has no webhook host to declare. GitHub validates that URL at
                            submission and refuses the manifest, so nothing is created: not a working App minus
                            automatic scanning, no App and no integration at all.
                          </p>
                        </>
                      ) : (
                        <>
                          <p className="font-medium text-foreground">
                            GitHub will reject a new App while <code>PUBLIC_API_URL</code> is not an address
                            GitHub can reach.
                          </p>
                          <p>
                            <code>PUBLIC_API_URL</code> is <code>{status.public_api_url}</code>, which resolves
                            only on this machine or inside this network: a localhost address, a private or LAN
                            address, or a name that exists only here. The App manifest declares that host as its
                            webhook URL, and GitHub validates it at submission, refusing any address it cannot
                            reach over the public internet (&quot;Hook url is not supported because it
                            isn&apos;t reachable over the public Internet&quot;). Nothing is created, so this is
                            not a working App minus automatic scanning; it is no App and no integration at all.
                          </p>
                        </>
                      )}
                      <p>
                        Set <code>PUBLIC_API_URL</code> to a publicly reachable URL, then restart the{" "}
                        <code>backend</code> and <code>celery-worker</code> services to pick it up. For local work
                        a tunnel is the usual answer, and{" "}
                        <code>cloudflared tunnel --url http://localhost:8000</code> needs no account.
                      </p>
                      <p>
                        There is no API to change an App&apos;s webhook URL after it is created, only its GitHub
                        settings page by hand, so a throwaway tunnel URL has to be re-entered there every time the
                        tunnel restarts. A named tunnel or a real domain is the better default for anything past
                        one test.
                      </p>
                      <p>
                        <code>PUBLIC_BASE_URL</code> can stay on localhost for a solo local setup: GitHub only
                        validates the webhook URL, and the App&apos;s redirect URL is followed by your own
                        browser. The cost is that every link Toleman posts into a pull request points at a host
                        only this machine can reach.
                      </p>
                    </div>
                  </div>
                )}
                {/* Advisory, not a block: see hostIsDotless. The backend only
                    refuses what it is certain about, and this case is merely
                    near-certain, so the operator keeps the click. */}
                {status.webhook_reachable && hostIsDotless(status.public_api_url) && (
                  <div className="flex gap-2 rounded-md border border-border bg-secondary p-3">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                    <p className="text-xs text-muted-foreground">
                      <code>PUBLIC_API_URL</code> is <code>{status.public_api_url}</code>, whose host has no dot
                      in it. A single-label name like that resolves only inside your own network, so GitHub will
                      most likely reject the App manifest for it the same way it rejects a localhost address.
                      Toleman cannot see your DNS, so this is a warning rather than a block: connect anyway if
                      that name really is publicly resolvable.
                    </p>
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {status.apps.length > 0
                    ? "Register another GitHub App (e.g. a separate dev/prod App, or one scoped to a different org):"
                    : "Leave blank to install on your personal account, or enter an org name to install there instead."}
                </p>
                <div className="flex gap-2">
                  <Input
                    aria-label="GitHub organization to install the App on (optional)"
                    className="bg-secondary"
                    placeholder="Organization (optional)"
                    value={org}
                    onChange={(e) => setOrg(e.target.value)}
                  />
                  <Button
                    onClick={connect}
                    disabled={connecting || !status.webhook_reachable}
                    className="shrink-0"
                  >
                    {connecting ? "Redirecting..." : "Connect GitHub"}
                  </Button>
                </div>
                {error && <p className="text-xs text-destructive">{error}</p>}
              </div>
            </div>
          )}
        </AsyncContent>
      </CardContent>
    </Card>

    <ConfirmDialog
      open={pendingDelete !== null}
      title="Delete GitHub App"
      description={
        pendingDelete ? (
          <>
            Delete <span className="font-medium text-foreground">{pendingDelete.app_slug}</span> and every
            installation under it? This only removes Toleman&apos;s record of the App -- it stays installed on
            GitHub&apos;s side until removed from GitHub&apos;s own settings. Repos already synced from it are
            not removed.
          </>
        ) : null
      }
      confirmLabel="Delete"
      tone="destructive"
      loading={deleting}
      onConfirm={confirmDelete}
      onCancel={() => setPendingDelete(null)}
    />
    </>
  );
}
