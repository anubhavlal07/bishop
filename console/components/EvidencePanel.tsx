"use client";

import { useState } from "react";

import type { Evidence, InvestigatorReport } from "@/lib/types";
import { Empty } from "./primitives";

const KIND_STYLE: Record<string, { colour: string; label: string }> = {
  injection: { colour: "var(--color-injection)", label: "injection attempt" },
  mitigating: { colour: "var(--color-fp)", label: "argues against malice" },
  intel: { colour: "var(--color-escalate)", label: "threat intel" },
  detector: { colour: "var(--muted)", label: "detector" },
  observation: { colour: "var(--muted)", label: "observation" },
};

function EvidenceRow({ evidence }: { evidence: Evidence }) {
  const [open, setOpen] = useState(evidence.kind === "injection");
  const style = KIND_STYLE[evidence.kind] ?? KIND_STYLE.observation;
  const notable =
    evidence.kind === "injection" || evidence.kind === "mitigating";

  return (
    <li
      className="rounded border px-3 py-2"
      style={{
        borderColor: notable ? style.colour : "var(--edge)",
        background: notable ? `${style.colour}0f` : "transparent",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-2 text-left"
      >
        <span className="mt-1 text-[10px] muted">{open ? "▾" : "▸"}</span>
        <span className="flex-1">
          <span className="text-sm">{evidence.title}</span>
          {notable && (
            <span
              className="ml-2 text-[10px] uppercase tracking-wide"
              style={{ color: style.colour }}
            >
              {style.label}
            </span>
          )}
        </span>
        <span className="mono text-xs muted">
          {evidence.confidence.toFixed(2)}
        </span>
      </button>

      {open && (
        <div className="mt-2 pl-5">
          <p className="muted text-xs leading-relaxed">{evidence.detail}</p>

          {evidence.signals.length > 0 && (
            <div className="mt-2 space-y-1">
              {evidence.signals.map((signal) => (
                <div key={signal.detector} className="text-[11px]">
                  <span className="mono" style={{ color: "var(--color-btp)" }}>
                    {signal.detector}
                  </span>
                  <span className="muted"> scored </span>
                  <span className="mono">{signal.score.toFixed(2)}</span>
                  {signal.mitigating && (
                    <span className="ml-1" style={{ color: "var(--color-fp)" }}>
                      (mitigating)
                    </span>
                  )}
                  {signal.rationale && (
                    <p className="muted mt-0.5 leading-relaxed">
                      {signal.rationale}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}

          {evidence.kind === "injection" &&
            typeof evidence.facts.raw_value === "string" && (
              <div className="mt-2">
                <p className="text-[10px] uppercase tracking-wide muted">
                  the field, verbatim — preserved, not stripped
                </p>
                <pre
                  className="mono mt-1 max-h-40 overflow-auto rounded p-2 text-[11px] whitespace-pre-wrap break-all"
                  style={{
                    background: "var(--bg)",
                    border: "1px solid var(--edge)",
                  }}
                >
                  {evidence.facts.raw_value}
                </pre>
              </div>
            )}
        </div>
      )}
    </li>
  );
}

export function EvidencePanel({ reports }: { reports: InvestigatorReport[] }) {
  if (reports.length === 0)
    return <Empty>No investigator has reported yet.</Empty>;

  return (
    <div className="space-y-4">
      {reports.map((report) => (
        <div key={report.investigator}>
          <div className="flex items-baseline gap-2">
            <h3 className="text-sm font-medium">{report.investigator}</h3>
            {report.duration_ms > 0 && (
              <span className="mono text-[10px] muted">
                {report.duration_ms}ms
              </span>
            )}
            {report.skipped && (
              <span className="text-[10px] muted">(skipped)</span>
            )}
          </div>
          {report.summary && (
            <p className="muted mt-1 text-xs leading-relaxed">
              {report.summary}
            </p>
          )}
          {report.evidence.length > 0 ? (
            <ul className="mt-2 space-y-1.5">
              {report.evidence.map((evidence) => (
                <EvidenceRow key={evidence.evidence_id} evidence={evidence} />
              ))}
            </ul>
          ) : (
            <p className="muted mt-1 text-[11px]">Nothing on this surface.</p>
          )}
        </div>
      ))}
    </div>
  );
}
