"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

// Issue #470: the credential the active scanner presents. Without one every
// probe is anonymous, so any route behind authentication answers 401 and the
// scan still reports zero findings -- an all-clear that is evidence of
// nothing.
//
// The stored value is never sent back by the API, not even masked, so this
// component can only ever show whether a credential is configured and under
// which header name. That is why there is no "edit" state: the operations
// are replace and clear.
export function ApiScanCredential({ targetId }: { targetId: number }) {
  const [configured, setConfigured] = useState(false);
  const [savedName, setSavedName] = useState<string | null>(null);
  const [name, setName] = useState("Authorization");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ accepted: boolean; detail: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getApiScanCredential(targetId)
      .then((s) => {
        if (cancelled) return;
        setConfigured(s.configured);
        setSavedName(s.header_name);
        if (s.header_name) setName(s.header_name);
      })
      .catch(() => {
        /* status is advisory; a failed read must not block the form */
      });
    return () => {
      cancelled = true;
    };
  }, [targetId]);

  async function run(action: () => Promise<void>, fallbackMessage: string) {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : fallbackMessage);
    } finally {
      setBusy(false);
    }
  }

  const save = () =>
    run(async () => {
      const res = await api.setApiScanCredential(targetId, name.trim(), value);
      setConfigured(res.configured);
      setSavedName(res.header_name);
      // Cleared from component state the moment it is stored: there is no
      // reason for the plaintext to stay in the page after this point.
      setValue("");
    }, "could not save the credential");

  const clear = () =>
    run(async () => {
      const res = await api.clearApiScanCredential(targetId);
      setConfigured(res.configured);
      setSavedName(null);
      setValue("");
    }, "could not clear the credential");

  const test = () =>
    run(async () => {
      const res = await api.testApiScanCredential(targetId);
      setTestResult({ accepted: res.accepted, detail: res.detail });
    }, "could not test the credential");

  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={`api-auth-value-${targetId}`} className="text-xs text-muted-foreground">
        Scan credential (for Active API Scanning)
      </Label>
      <div className="flex items-center gap-2">
        <Input
          aria-label="Header name"
          placeholder="Authorization"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={busy}
          className="max-w-[12rem]"
        />
        <Input
          id={`api-auth-value-${targetId}`}
          type="password"
          placeholder={configured ? "Replace the stored value…" : "Bearer …"}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={busy}
          className="max-w-md"
          aria-describedby={`api-auth-${targetId}-hint`}
        />
        <Button size="sm" variant="outline" onClick={save} disabled={busy || !name.trim() || !value.trim()}>
          {busy ? "Working…" : "Save"}
        </Button>
        {configured && (
          <>
            <Button size="sm" variant="ghost" onClick={test} disabled={busy}>
              Test
            </Button>
            <Button size="sm" variant="ghost" onClick={clear} disabled={busy}>
              Clear
            </Button>
          </>
        )}
      </div>
      <p id={`api-auth-${targetId}-hint`} className="text-xs text-muted-foreground">
        {configured
          ? `Sent as the ${savedName} header on every active scan. The stored value is never shown again — save a new one to replace it.`
          : "Without a credential, scans run anonymously and authenticated routes answer 401, which looks identical to a clean API."}
      </p>
      {testResult && (
        <p className={`text-xs ${testResult.accepted ? "text-muted-foreground" : "text-destructive"}`}>
          {testResult.detail}
        </p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
