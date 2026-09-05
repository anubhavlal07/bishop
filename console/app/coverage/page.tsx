"use client";

import { useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api";
import type { Coverage, CoverageEntry } from "@/lib/types";
import { ApiDown, Panel } from "@/components/primitives";

/** ATT&CK's tactic order, so the matrix reads left to right as an intrusion does. */
const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export default function CoveragePage() {
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setCoverage(await api.coverage());
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
  }, []);

  const columns = useMemo(() => {
    if (!coverage) return [];
    const grouped = new Map<string, CoverageEntry[]>();
    for (const entry of coverage.entries) {
      const tactics = entry.tactics.length > 0 ? entry.tactics : ["unmapped"];
      for (const tactic of tactics) {
        const key = tactic
          .split("-")
          .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
          .join(" ");
        grouped.set(key, [...(grouped.get(key) ?? []), entry]);
      }
    }
    return [...grouped.entries()].sort((a, b) => {
      const ai = TACTIC_ORDER.indexOf(a[0]);
      const bi = TACTIC_ORDER.indexOf(b[0]);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });
  }, [coverage]);

  if (error) return <ApiDown message={error} />;
  if (!coverage) return <p className="muted text-xs">Loading the coverage matrix…</p>;

  return (
    <Panel title="ATT&CK coverage" subtitle={`v${coverage.attack_version}`}>
      <p className="text-xs leading-relaxed">{coverage.summary}.</p>
      <p className="muted mt-2 text-xs leading-relaxed">
        <span style={{ color: "var(--color-fp)" }}>Covered</span> means a deterministic detector
        maps to the technique <em>and</em> a labelled fixture exercises it.{" "}
        <span style={{ color: "var(--color-escalate)" }}>Untested</span> means the detector
        exists but nothing in the golden set produces it — real coverage, unproven coverage.
        Coverage of a technique is also not detection of every implementation of it.
      </p>

      <div className="mt-4 overflow-x-auto">
        <div className="flex gap-3" style={{ minWidth: "max-content" }}>
          {columns.map(([tactic, entries]) => (
            <div key={tactic} className="w-52 shrink-0">
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide muted">
                {tactic}
              </h3>
              <ul className="space-y-1">
                {entries
                  .slice()
                  .sort((a, b) => a.technique_id.localeCompare(b.technique_id))
                  .map((entry) => {
                    const colour =
                      entry.status === "covered"
                        ? "var(--color-fp)"
                        : entry.status === "untested"
                          ? "var(--color-escalate)"
                          : "var(--muted)";
                    return (
                      <li
                        key={`${tactic}-${entry.technique_id}`}
                        className="rounded border px-2 py-1.5"
                        style={{ borderColor: colour, background: `${colour}0f` }}
                        title={`${entry.detectors.join(", ")}${
                          entry.fixtures.length ? ` · fixtures: ${entry.fixtures.join(", ")}` : ""
                        }`}
                      >
                        <a
                          href={entry.url}
                          target="_blank"
                          rel="noreferrer"
                          className="mono text-[11px]"
                          style={{ color: colour }}
                        >
                          {entry.technique_id}
                        </a>
                        <div className="text-[11px] leading-tight">{entry.name}</div>
                        <div className="muted mt-0.5 text-[10px]">
                          {entry.detectors.join(", ") || "no detector"}
                        </div>
                      </li>
                    );
                  })}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
