"use client";

import { useState } from "react";
import { api } from "@/lib/api";

// (#298) Clone credentials for a target on a host behind a VPN or requiring
// a client certificate (an internal GitHub Enterprise Server/GitLab/Gitea
// added to EXTRA_CLONE_HOSTS by the operator).
//
// The cert and key are write-only, deliberately, and this component is built
// around that rather than around it: the API returns `client_cert_set`/
// `client_key_set` booleans and never the PEM itself, the same
// "token_set, not the token" shape Admin > Global Integrations uses for the
// GitHub token. So there is no "current value" to prefill, editing means
// replacing, and the only honest thing to render for an already-stored
// credential is that it exists.
//
// The proxy URL is a plain setting, not a secret: it rides on the normal
// PATCH /api/targets/{id} path with the rest of the target's config, while
// the PEMs go to the dedicated clone-credentials endpoint that encrypts
// them at rest.
export function TargetCloneCredentials({
  targetId,
  initialCertSet,
  initialKeySet,
  initialProxyUrl,
}: {
  targetId: number;
  initialCertSet: boolean;
  initialKeySet: boolean;
  initialProxyUrl: string;
}) {
  const [certSet, setCertSet] = useState(initialCertSet);
  const [keySet, setKeySet] = useState(initialKeySet);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [proxyUrl, setProxyUrl] = useState(initialProxyUrl);
  const [savedProxyUrl, setSavedProxyUrl] = useState(initialProxyUrl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const proxyChanged = proxyUrl !== savedProxyUrl;
  const nothingToSave = !certPem && !keyPem && !proxyChanged;

  async function save() {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      if (proxyChanged) {
        await api.updateTarget(targetId, { clone_proxy_url: proxyUrl });
        setSavedProxyUrl(proxyUrl);
      }
      // Only the fields actually filled in are sent: the endpoint treats an
      // omitted field as "leave it alone" and an empty string as "clear it",
      // so sending a blank textarea for an untouched credential would wipe a
      // stored one.
      if (certPem || keyPem) {
        const result = await api.saveCloneCredentials(targetId, {
          ...(certPem ? { client_cert_pem: certPem } : {}),
          ...(keyPem ? { client_key_pem: keyPem } : {}),
        });
        setCertSet(result.client_cert_set);
        setKeySet(result.client_key_set);
        setCertPem("");
        setKeyPem("");
      }
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save clone credentials");
    } finally {
      setBusy(false);
    }
  }

  async function clearCredentials() {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      // Explicit empty strings, which is what this endpoint reads as "clear".
      const result = await api.saveCloneCredentials(targetId, {
        client_cert_pem: "",
        client_key_pem: "",
      });
      setCertSet(result.client_cert_set);
      setKeySet(result.client_key_set);
      setCertPem("");
      setKeyPem("");
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to clear clone credentials");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[11px] text-muted-foreground">
        Only needed for a target whose repo host is not github.com, sits behind a VPN, or requires
        a client certificate. The host itself must also be in the deployment&apos;s{" "}
        <code className="rounded bg-secondary px-1">EXTRA_CLONE_HOSTS</code>; a target on a host
        that is not will be rejected when it is created, before any of this is reached.
      </p>

      <div className="flex flex-wrap items-center gap-3">
        <label htmlFor="clone-proxy-url" className="text-xs text-muted-foreground">
          Clone proxy URL:
        </label>
        <input
          id="clone-proxy-url"
          type="text"
          className="h-8 min-w-72 rounded-md border border-input bg-background px-2 text-xs"
          placeholder="http://vpn-gateway.internal.corp:3128"
          value={proxyUrl}
          disabled={busy}
          onChange={(e) => setProxyUrl(e.target.value)}
          aria-describedby="clone-proxy-help"
        />
        <span id="clone-proxy-help" className="text-[11px] text-muted-foreground">
          Set as HTTPS_PROXY/HTTP_PROXY for this target&apos;s clone only. Blank to clear.
        </span>
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="client-cert-pem" className="text-xs text-muted-foreground">
          Client certificate (PEM){" "}
          <span className={certSet ? "text-foreground" : ""}>
            {certSet ? "(stored)" : "(not set)"}
          </span>
        </label>
        <textarea
          id="client-cert-pem"
          rows={3}
          className="rounded-md border border-input bg-background p-2 font-mono text-[11px]"
          placeholder={certSet ? "Paste a new PEM to replace the stored one" : "-----BEGIN CERTIFICATE-----"}
          value={certPem}
          disabled={busy}
          onChange={(e) => setCertPem(e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="client-key-pem" className="text-xs text-muted-foreground">
          Client private key (PEM){" "}
          <span className={keySet ? "text-foreground" : ""}>
            {keySet ? "(stored)" : "(not set)"}
          </span>
        </label>
        <textarea
          id="client-key-pem"
          rows={3}
          className="rounded-md border border-input bg-background p-2 font-mono text-[11px]"
          placeholder={keySet ? "Paste a new PEM to replace the stored one" : "-----BEGIN PRIVATE KEY-----"}
          value={keyPem}
          disabled={busy}
          onChange={(e) => setKeyPem(e.target.value)}
        />
        <span className="text-[11px] text-muted-foreground">
          Encrypted at rest and never sent back to this page; it can be replaced or cleared, not read.
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={save}
          disabled={busy || nothingToSave}
          className="h-8 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground disabled:opacity-50"
        >
          {busy ? "Saving..." : "Save"}
        </button>
        {(certSet || keySet) && (
          <button
            type="button"
            onClick={clearCredentials}
            disabled={busy}
            className="h-8 rounded-md border border-input px-3 text-xs disabled:opacity-50"
          >
            Clear stored certificate and key
          </button>
        )}
        {saved && !error && <span className="text-xs text-muted-foreground">Saved.</span>}
        {error && <p className="text-xs text-destructive">{error}</p>}
      </div>
    </div>
  );
}
