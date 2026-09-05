"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { DetectorSpec } from "@/lib/types";
import { ApiDown, Panel } from "@/components/primitives";

export default function DetectorsPage() {
  const [data, setData] = useState<{ surfaces: string[]; detectors: DetectorSpec[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const result = await api.detectors();
        setData({ surfaces: result.surfaces, detectors: result.detectors });
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
  }, []);

  if (error) return <ApiDown message={error} />;
  if (!data) return <p className="muted text-xs">Loading the detector library…</p>;

  return (
    <Panel title="Detector library" subtitle={`${data.detectors.length} deterministic primitives`}>
      <p className="muted mb-4 text-xs leading-relaxed">
        Every signal behind a verdict starts here, in a pure function with a unit test beside it.
        No model call, no network, no clock read, no randomness — the same alert produces the same
        result on any machine. Agents interpret and correlate these; they do not invent signals,
        and a finding citing a detector that did not fire is dropped rather than downgraded.
      </p>

      <div className="space-y-5">
        {data.surfaces.map((surface) => {
          const specs = data.detectors.filter((d) => d.surface === surface);
          if (specs.length === 0) return null;
          return (
            <div key={surface}>
              <h3 className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-btp)" }}>
                {surface}
                <span className="muted ml-2 font-normal normal-case">
                  {specs.length} detector{specs.length === 1 ? "" : "s"}
                </span>
              </h3>
              <ul className="mt-2 space-y-2">
                {specs.map((spec) => (
                  <li
                    key={spec.name}
                    className="rounded border px-3 py-2"
                    style={{ borderColor: "var(--edge)" }}
                  >
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="mono text-sm">{spec.name}</span>
                      {spec.techniques.map((technique) => (
                        <a
                          key={technique}
                          href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="mono rounded px-1 text-[10px]"
                          style={{ border: "1px solid var(--edge)", color: "var(--muted)" }}
                        >
                          {technique}
                        </a>
                      ))}
                    </div>
                    <p className="muted mt-1 text-xs leading-relaxed">{spec.summary}</p>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
