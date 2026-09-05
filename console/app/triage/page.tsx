"use client";

/**
 * Bring your own alert.
 *
 * Everything else in this console reads the thirty committed fixtures. This is
 * the page where someone points Bishop at an alert they actually have, which
 * is the difference between watching a demo and using a tool.
 *
 * The flow is deliberately two-step. Paste, then *preview*, then run. The
 * preview shows what Bishop understood and — the part that matters — which
 * detectors have jurisdiction over what survived the mapping. Bishop reads a
 * subset of any real alert, and a verdict is only worth as much as the fields
 * behind it, so seeing the subset before the verdict is not a nicety.
 */

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { Panel } from "@/components/primitives";
import { api, ApiError } from "@/lib/api";
import type { IngestPreview } from "@/lib/types";

/** Starting points, so the page is not an empty box with no way in. */
const SAMPLES: { name: string; blurb: string; body: unknown }[] = [
  {
    name: "Sysmon process create",
    blurb: "Raw Windows event JSON. Encoded PowerShell under a Word parent.",
    body: {
      EventID: 1,
      UtcTime: "2026-09-05 11:22:33.123",
      Computer: "WKSTN-903",
      User: "CORP\\a.smith",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CommandLine:
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      ParentImage: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      ProcessId: 4242,
      RuleName: "Office application spawned PowerShell",
    },
  },
  {
    name: "Elastic / ECS document",
    blurb: "Nested ECS fields. A credential-dumping command line.",
    body: {
      "@timestamp": "2026-09-05T11:22:33.000Z",
      event: { module: "endpoint", severity: 73 },
      host: { hostname: "SRV-APP-11", ip: "10.0.0.11" },
      user: { name: "svc_worker", domain: "CORP" },
      process: {
        name: "rundll32.exe",
        executable: "C:\\Windows\\System32\\rundll32.exe",
        command_line: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 908 out.dmp full",
      },
      rule: { name: "Credential access attempt", id: "R-114" },
    },
  },
  {
    name: "Beaconing, many connections",
    blurb: "Bishop's own schema. A rhythm no single event shows.",
    body: {
      alert_id: "MY-BEACON-1",
      source: "proxy",
      rule_name: "Repeated outbound connections",
      detected_at: "2026-09-05T09:00:00Z",
      severity: "low",
      device: { hostname: "WKSTN-410", ip: "10.0.0.41" },
      principal: { username: "k.owusu", domain: "CORP" },
      connections: Array.from({ length: 20 }, (_, i) => ({
        timestamp: new Date(Date.UTC(2026, 8, 5, 9, 0, 0) + i * 300_000 + (i % 2 ? 9000 : -9000))
          .toISOString(),
        hostname: "cdn-telemetry.example",
        dest_ip: "203.0.113.44",
        dest_port: 443,
        bytes_out: 1180,
        bytes_in: 340,
      })),
    },
  },
  {
    name: "Something Bishop cannot read",
    blurb: "A Kerberoasting ticket count. Shows the honest failure mode.",
    body: {
      rule_name: "Unusual volume of service ticket requests",
      ticket_encryption: "RC4-HMAC",
      service_tickets_requested: 40,
      window_seconds: 120,
    },
  },
];

export default function TriagePage() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<IngestPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"preview" | "run" | null>(null);
  const [formats, setFormats] = useState<Record<string, string> | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api
      .ingestFormats()
      .then((r) => setFormats(r.formats))
      .catch(() => setFormats(null));
  }, []);

  /** Parse locally first, so a typo is a typo and not a round trip. */
  const parse = useCallback((): unknown | null => {
    const trimmed = text.trim();
    if (!trimmed) {
      setError("Paste an alert, or load one of the samples below.");
      return null;
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        if (parsed.length !== 1) {
          setError(
            `This is an array of ${parsed.length} alerts. Bishop triages one at a time here — submit them individually.`,
          );
          return null;
        }
        return parsed[0];
      }
      if (typeof parsed !== "object" || parsed === null) {
        setError("Expected a JSON object describing one alert.");
        return null;
      }
      return parsed;
    } catch (cause) {
      setError(
        `That is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
      return null;
    }
  }, [text]);

  const runPreview = useCallback(async () => {
    setError(null);
    const payload = parse();
    if (!payload) return;
    setBusy("preview");
    try {
      setPreview(await api.previewIngest(payload));
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause));
      setPreview(null);
    } finally {
      setBusy(null);
    }
  }, [parse]);

  const runTriage = useCallback(async () => {
    setError(null);
    const payload = parse();
    if (!payload) return;
    setBusy("run");
    try {
      const started = await api.startRunFromAlert(payload);
      router.push(`/runs/${started.run_id}`);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause));
      setBusy(null);
    }
  }, [parse, router]);

  const loadFile = useCallback(async (file: File) => {
    setError(null);
    setPreview(null);
    const body = await file.text();
    setText(body.trim());
  }, []);

  return (
    <div className="grid gap-4 lg:grid-cols-[1.1fr_1fr]">
      <div className="space-y-4">
        <Panel
          title="Triage your own alert"
          subtitle="Sysmon, ECS, or any JSON with recognisable field names"
        >
          <p className="muted mb-3 text-xs leading-relaxed">
            Paste one alert as JSON, or drop a file. Bishop maps it onto its own schema
            best-effort and tells you exactly what it read — a verdict is only worth as much as
            the fields behind it, so check the mapping before you trust the answer.
          </p>

          <textarea
            value={text}
            onChange={(event) => {
              setText(event.target.value);
              setPreview(null);
            }}
            onDrop={(event) => {
              event.preventDefault();
              const file = event.dataTransfer.files?.[0];
              if (file) void loadFile(file);
            }}
            onDragOver={(event) => event.preventDefault()}
            spellCheck={false}
            placeholder='{ "Computer": "WKSTN-01", "CommandLine": "powershell.exe -enc ..." }'
            className="mono h-72 w-full resize-y rounded border p-3 text-xs leading-relaxed outline-none"
            style={{
              borderColor: "var(--edge)",
              background: "var(--bg)",
              color: "var(--text)",
            }}
          />

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              onClick={() => void runPreview()}
              disabled={busy !== null}
              className="rounded px-3 py-1.5 text-sm"
              style={{ border: "1px solid var(--edge)", opacity: busy ? 0.5 : 1 }}
            >
              {busy === "preview" ? "Mapping…" : "Preview the mapping"}
            </button>

            <button
              onClick={() => void runTriage()}
              disabled={busy !== null}
              className="rounded px-3 py-1.5 text-sm font-medium"
              style={{
                background: "var(--color-escalate)",
                color: "#0b0d10",
                opacity: busy ? 0.5 : 1,
              }}
            >
              {busy === "run" ? "Starting…" : "Triage it"}
            </button>

            <button
              onClick={() => fileInput.current?.click()}
              className="muted rounded px-3 py-1.5 text-sm"
              style={{ border: "1px solid var(--edge)" }}
            >
              Load a file
            </button>
            <input
              ref={fileInput}
              type="file"
              accept=".json,.ndjson,.txt,application/json"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void loadFile(file);
              }}
            />

            {text && (
              <button
                onClick={() => {
                  setText("");
                  setPreview(null);
                  setError(null);
                }}
                className="muted ml-auto text-xs underline"
              >
                clear
              </button>
            )}
          </div>

          {error && (
            <p
              className="mt-3 rounded border p-2 text-xs"
              style={{ borderColor: "var(--color-tp)", color: "var(--color-tp)" }}
            >
              {error}
            </p>
          )}
        </Panel>

        <Panel title="Start from a sample" subtitle="Four shapes, including one that fails">
          <ul className="space-y-2">
            {SAMPLES.map((sample) => (
              <li key={sample.name}>
                <button
                  onClick={() => {
                    setText(JSON.stringify(sample.body, null, 2));
                    setPreview(null);
                    setError(null);
                  }}
                  className="w-full rounded border p-2 text-left transition-colors hover:bg-white/5"
                  style={{ borderColor: "var(--edge)" }}
                >
                  <div className="text-sm">{sample.name}</div>
                  <div className="muted text-xs">{sample.blurb}</div>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="space-y-4">
        {preview ? (
          <MappingPanel preview={preview} />
        ) : (
          <Panel title="What Bishop read" subtitle="preview an alert to see this">
            <p className="muted text-xs leading-relaxed">
              The mapping report lands here. It lists every field Bishop understood, every one it
              ignored, anything it had to default — and which detectors have jurisdiction over
              what is left.
            </p>
            <p className="muted mt-3 text-xs leading-relaxed">
              That last list is the one to read. It is computed by running the detectors and
              asking which had data in their remit, so if it is empty Bishop will escalate
              whatever your alert says, because it has nothing it can measure. Better to know
              that now than after a run.
            </p>
          </Panel>
        )}

        {formats && (
          <Panel title="Formats it recognises" subtitle="detection is advisory">
            <dl className="space-y-2">
              {Object.entries(formats).map(([name, detail]) => (
                <div key={name}>
                  <dt className="mono text-xs">{name}</dt>
                  <dd className="muted text-xs">{detail}</dd>
                </div>
              ))}
            </dl>
            <p className="muted mt-3 text-xs leading-relaxed">
              Every payload is tried against every alias table regardless of what was detected,
              so a hybrid or partial shape still maps as far as it can.
            </p>
          </Panel>
        )}
      </div>
    </div>
  );
}

function MappingPanel({ preview }: { preview: IngestPreview }) {
  const { mapping, usable } = preview;
  return (
    <Panel
      title="What Bishop read"
      subtitle={`detected as ${mapping.detected_format}`}
      right={
        <span
          className="rounded px-2 py-0.5 text-xs"
          style={{
            color: usable ? "var(--color-btp)" : "var(--color-tp)",
            border: `1px solid ${usable ? "var(--color-btp)" : "var(--color-tp)"}`,
          }}
        >
          {usable ? "can be assessed" : "nothing to measure"}
        </span>
      }
    >
      <section className="mb-4">
        <h4 className="mb-1 text-xs font-medium">
          {mapping.detectors_with_jurisdiction.length} detectors can examine this
        </h4>
        {mapping.detectors_with_jurisdiction.length > 0 ? (
          <p className="mono muted text-xs leading-relaxed">
            {mapping.detectors_with_jurisdiction.join(", ")}
          </p>
        ) : (
          <p className="text-xs leading-relaxed" style={{ color: "var(--color-tp)" }}>
            None. Bishop will escalate this rather than reach a verdict — which is the correct
            behaviour, but means the run will not tell you much. A command line, a set of
            connections or a list of auth events gives it something to measure.
          </p>
        )}
      </section>

      {mapping.warnings.length > 0 && (
        <section className="mb-4">
          <h4 className="mb-1 text-xs font-medium">Worth knowing</h4>
          <ul className="space-y-1">
            {mapping.warnings.map((warning) => (
              <li key={warning} className="muted text-xs leading-relaxed">
                {warning}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="mb-4">
        <h4 className="mb-1 text-xs font-medium">
          Understood — {mapping.mapped.length} field{mapping.mapped.length === 1 ? "" : "s"}
        </h4>
        <ul className="mono grid grid-cols-1 gap-0.5 text-xs sm:grid-cols-2">
          {mapping.mapped.map((entry) => (
            <li key={`${entry.from}->${entry.to}`} className="muted truncate">
              {entry.from} <span className="opacity-50">→</span> {entry.to}
            </li>
          ))}
        </ul>
      </section>

      {mapping.defaulted.length > 0 && (
        <section className="mb-4">
          <h4 className="mb-1 text-xs font-medium">Defaulted</h4>
          <ul className="space-y-1.5">
            {mapping.defaulted.map((entry) => (
              <li key={entry.field} className="text-xs">
                <span className="mono">
                  {entry.field} = {entry.value}
                </span>
                <div className="muted leading-relaxed">{entry.why}</div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {mapping.ignored.length > 0 && (
        <section>
          <h4 className="mb-1 text-xs font-medium">
            Ignored — {mapping.ignored.length} field{mapping.ignored.length === 1 ? "" : "s"}
          </h4>
          <p className="mono muted text-xs leading-relaxed">{mapping.ignored.join(", ")}</p>
          <p className="muted mt-1 text-xs leading-relaxed">
            Kept in <code>raw</code> and still scanned for injection, but nothing interprets
            them — Bishop does not guess that an unrecognised field is a hostname.
          </p>
        </section>
      )}

      <p className="muted mt-4 border-t pt-3 text-xs" style={{ borderColor: "var(--edge)" }}>
        Happy with this? <Link href="#" className="underline">Triage it</Link> using the button on
        the left.
      </p>
    </Panel>
  );
}
