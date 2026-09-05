"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { AlertSummary } from "@/lib/types";
import {
  ApiDown,
  Panel,
  SeverityDot,
  VerdictPill,
} from "@/components/primitives";

export default function AlertsPage() {
  const router = useRouter();
  const [alerts, setAlerts] = useState<AlertSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setAlerts((await api.alerts()).alerts);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
  }, []);

  const start = async (alertId: string) => {
    setStarting(alertId);
    try {
      const { run_id } = await api.startRun(alertId);
      router.push(`/runs/${run_id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setStarting(null);
    }
  };

  if (error) return <ApiDown message={error} />;

  return (
    <div className="space-y-4">
      <Panel
        title="Alert queue"
        subtitle={alerts ? `${alerts.length} labelled alerts` : "loading…"}
      >
        <p className="muted mb-4 text-xs leading-relaxed">
          These alerts are synthetic and hand-labelled. They exist so
          Bishop&apos;s behaviour can be measured against known ground truth —
          they are not evidence that it works on real-world noise, because they
          contain none. This is also the set the thresholds were tuned against,
          so it flatters; the held-out set in <code>fixtures/holdout/</code> is
          the honest number. The expected verdict is shown here for reading the
          demo; Bishop never sees it.
        </p>

        {!alerts ? (
          <p className="muted text-xs">Loading the corpus…</p>
        ) : (
          <ul className="divide-y" style={{ borderColor: "var(--edge)" }}>
            {alerts.map((alert) => (
              <li key={alert.alert_id}>
                <button
                  type="button"
                  disabled={starting !== null}
                  onClick={() => void start(alert.alert_id)}
                  className="flex w-full flex-wrap items-center gap-3 px-1 py-2.5 text-left hover:opacity-80 disabled:opacity-40"
                >
                  <SeverityDot severity={alert.severity} />
                  <span className="mono w-64 shrink-0 text-xs">
                    {alert.alert_id}
                  </span>
                  <span className="flex-1 text-sm">{alert.rule_name}</span>
                  <span className="muted hidden w-40 shrink-0 text-xs md:block">
                    {alert.host ?? alert.user ?? alert.source}
                  </span>
                  <VerdictPill label={alert.expected_verdict} />
                  <span className="muted w-16 shrink-0 text-right text-[11px]">
                    {starting === alert.alert_id ? "starting…" : "triage →"}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
