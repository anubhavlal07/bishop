"use client";

import { useCallback, useEffect, useState } from "react";

import { API_BASE } from "@/lib/api";
import {
  clearCredentials,
  loadCredentials,
  saveCredentials,
  type ProviderInfo,
  type StoredCredentials,
} from "@/lib/credentials";

export function ProviderSetup({
  open,
  onClose,
  dismissable = true,
}: {
  open: boolean;
  onClose: () => void;
  dismissable?: boolean;
}) {
  const [providers, setProviders] = useState<ProviderInfo[] | null>(null);
  const [note, setNote] = useState("");
  const [choice, setChoice] = useState<string>("");
  const [apiKey, setApiKey] = useState("");
  const [modelId, setModelId] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    fetch(`${API_BASE}/providers`, { cache: "no-store" })
      .then((r) => r.json())
      .then((body) => {
        setProviders(body.providers);
        setNote(body.note ?? "");
        const existing = loadCredentials();
        const initial = existing?.provider ?? body.providers[0]?.key ?? "";
        setChoice(initial);
        setApiKey(existing?.apiKey ?? "");
        setModelId(existing?.modelId ?? "");
        setEndpoint(existing?.endpoint ?? "");
      })
      .catch(() =>
        setError(`Cannot reach Bishop's API at ${API_BASE}. Is it running?`),
      );
  }, [open]);

  const selected = providers?.find((p) => p.key === choice) ?? null;

  const pick = useCallback((provider: ProviderInfo) => {
    setChoice(provider.key);
    setModelId(provider.default_model);
    setError(null);
  }, []);

  const save = useCallback(async () => {
    if (!selected) return;
    setError(null);

    const credentials: StoredCredentials = {
      provider: selected.key,
      apiKey: selected.key === "mock" ? "" : apiKey.trim(),
      modelId: modelId.trim() || selected.default_model,
      endpoint: endpoint.trim() || undefined,
    };

    if (selected.key === "mock") {
      saveCredentials(credentials);
      onClose();
      return;
    }

    setBusy(true);
    try {
      const headers: Record<string, string> = {
        "X-Model-Provider": credentials.provider,
        "X-Model-Key": credentials.apiKey,
        "X-Model-Id": credentials.modelId,
      };
      if (credentials.endpoint)
        headers["X-Model-Endpoint"] = credentials.endpoint;

      const response = await fetch(`${API_BASE}/providers/verify`, {
        method: "POST",
        headers,
      });
      const body = await response.json().catch(() => ({}));

      if (!response.ok) {
        setError(body.detail ?? `Verification failed (${response.status}).`);
        return;
      }
      if (!body.ok) {
        setError(body.detail ?? "The provider rejected that key.");
        return;
      }

      saveCredentials({ ...credentials, verifiedAt: new Date().toISOString() });
      onClose();
    } catch {
      setError(`Cannot reach Bishop's API at ${API_BASE}.`);
    } finally {
      setBusy(false);
    }
  }, [selected, apiKey, modelId, endpoint, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      style={{ background: "rgba(0,0,0,0.72)" }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="provider-setup-title"
    >
      <div
        className="w-full max-w-2xl rounded-lg border p-5"
        style={{ borderColor: "var(--edge)", background: "var(--panel)" }}
      >
        <h2 id="provider-setup-title" className="text-base font-semibold">
          Choose a model
        </h2>
        <p className="muted mt-1 text-xs leading-relaxed">
          Bishop&apos;s detectors, ATT&amp;CK mapping, injection scanning and
          audit chain run without any model at all. A model adds the judgement
          on top: the narrative, and correlation across signals no single
          detector sees.
        </p>

        {error && (
          <p
            className="mt-3 rounded border p-2 text-xs"
            style={{ borderColor: "var(--color-tp)", color: "var(--color-tp)" }}
          >
            {error}
          </p>
        )}

        {!providers ? (
          <p className="muted mt-4 text-xs">Loading providers…</p>
        ) : (
          <>
            <div className="mt-4 grid gap-2 sm:grid-cols-2">
              {providers.map((provider) => {
                const active = provider.key === choice;
                return (
                  <button
                    key={provider.key}
                    onClick={() => pick(provider)}
                    className="rounded border p-2 text-left"
                    style={{
                      borderColor: active
                        ? "var(--color-escalate)"
                        : "var(--edge)",
                      background: active
                        ? "rgba(227,179,65,0.08)"
                        : "transparent",
                    }}
                  >
                    <div className="text-sm">{provider.label}</div>
                    <div className="muted text-xs">{provider.key_hint}</div>
                  </button>
                );
              })}
            </div>

            {selected && selected.key !== "mock" && (
              <div className="mt-4 space-y-3">
                <label className="block">
                  <span className="text-xs">API key</span>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(event) => setApiKey(event.target.value)}
                    placeholder={selected.key_hint}
                    autoComplete="off"
                    spellCheck={false}
                    className="mono mt-1 w-full rounded border p-2 text-xs outline-none"
                    style={{
                      borderColor: "var(--edge)",
                      background: "var(--bg)",
                      color: "var(--text)",
                    }}
                  />
                </label>

                <label className="block">
                  <span className="text-xs">Model</span>
                  <input
                    list={`models-${selected.key}`}
                    value={modelId}
                    onChange={(event) => setModelId(event.target.value)}
                    className="mono mt-1 w-full rounded border p-2 text-xs outline-none"
                    style={{
                      borderColor: "var(--edge)",
                      background: "var(--bg)",
                      color: "var(--text)",
                    }}
                  />
                  <datalist id={`models-${selected.key}`}>
                    {selected.models.map((model) => (
                      <option key={model} value={model} />
                    ))}
                  </datalist>
                </label>

                {selected.needs_endpoint && (
                  <label className="block">
                    <span className="text-xs">Resource endpoint</span>
                    <input
                      value={endpoint}
                      onChange={(event) => setEndpoint(event.target.value)}
                      placeholder="https://my-resource.openai.azure.com"
                      className="mono mt-1 w-full rounded border p-2 text-xs outline-none"
                      style={{
                        borderColor: "var(--edge)",
                        background: "var(--bg)",
                        color: "var(--text)",
                      }}
                    />
                    <span className="muted mt-1 block text-xs">
                      Must be an Azure OpenAI hostname. Bishop refuses anything
                      else — an unrestricted endpoint would let this server be
                      pointed at any address with your key attached.
                    </span>
                  </label>
                )}

                {selected.help_url && (
                  <a
                    href={selected.help_url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="muted inline-block text-xs underline"
                  >
                    Where to get a {selected.label} key
                  </a>
                )}
              </div>
            )}

            <div
              className="muted mt-4 rounded border p-3 text-xs leading-relaxed"
              style={{ borderColor: "var(--edge)" }}
            >
              <strong>Where your key goes.</strong> {note} It is sent as a
              request header on the runs that need it and used to build one
              provider for that run.
              <br />
              <br />
              It is stored in this browser&apos;s <code>localStorage</code>,
              which any script running on this origin can read — so a cross-site
              scripting bug here would be a key-theft bug. Bishop never puts it
              in a URL, never logs it, and never writes it to the audit chain.
              Clear it any time from Settings.
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <button
                onClick={() => void save()}
                disabled={busy || (selected?.key !== "mock" && !apiKey.trim())}
                className="rounded px-3 py-1.5 text-sm font-medium"
                style={{
                  background: "var(--color-escalate)",
                  color: "#0b0d10",
                  opacity:
                    busy || (selected?.key !== "mock" && !apiKey.trim())
                      ? 0.5
                      : 1,
                }}
              >
                {busy
                  ? "Verifying…"
                  : selected?.key === "mock"
                    ? "Use the deterministic model"
                    : "Verify and save"}
              </button>

              {loadCredentials() && (
                <button
                  onClick={() => {
                    clearCredentials();
                    setApiKey("");
                    onClose();
                  }}
                  className="muted rounded px-3 py-1.5 text-sm"
                  style={{ border: "1px solid var(--edge)" }}
                >
                  Forget my key
                </button>
              )}

              {dismissable && (
                <button
                  onClick={onClose}
                  className="muted ml-auto text-xs underline"
                >
                  not now
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
