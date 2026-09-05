"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Scorecard } from "@/lib/types";
import { ApiDown, Panel, VerdictPill } from "@/components/primitives";

function Metric({
  label,
  value,
  note,
  highlight,
}: {
  label: string;
  value: string;
  note?: string;
  highlight?: boolean;
}) {
  return (
    <div
      className="rounded border px-3 py-2.5"
      style={{
        borderColor: highlight ? "var(--color-btp)" : "var(--edge)",
        background: highlight ? "var(--color-btp)0f" : "transparent",
      }}
    >
      <div className="muted text-[11px] leading-tight">{label}</div>
      <div className="mono mt-1 text-lg">{value}</div>
      {note && <div className="muted mt-0.5 text-[10px] leading-tight">{note}</div>}
    </div>
  );
}

export default function ScorecardPage() {
  const [card, setCard] = useState<Scorecard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setCard(await api.scorecard());
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
  }, []);

  if (error) return <ApiDown message={error} />;
  if (!card) return <p className="muted text-xs">Loading the scorecard…</p>;

  const pct = (value: number) => `${(value * 100).toFixed(0)}%`;

  return (
    <div className="space-y-4">
      {/* The caveats come first on purpose. They are the most credible thing on
          this page, and a reader who only sees the numbers has been misled. */}
      <Panel title="Read this before quoting any number below">
        <ul className="space-y-2">
          {card.notes.map((note) => (
            <li key={note} className="text-xs leading-relaxed">
              {note}
            </li>
          ))}
        </ul>
      </Panel>

      <Panel
        title="Scorecard"
        subtitle={`${card.corpus_size} alerts · ${card.provider} (${card.model}) · ATT&CK v${card.attack_version}`}
      >
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide muted">Detection</h3>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Metric
            label="False-negative rate on true positives"
            value={pct(card.false_negative_rate)}
            note="the number a security person asks for first"
            highlight
          />
          <Metric label="Verdict accuracy" value={pct(card.verdict_accuracy)} />
          <Metric label="False-positive rate" value={pct(card.false_positive_rate)} />
          <Metric label="Benign-TP accuracy" value={pct(card.benign_tp_accuracy)} />
        </div>

        <h3 className="mb-2 mt-4 text-[11px] font-semibold uppercase tracking-wide muted">
          Abstention
        </h3>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Metric
            label="Escalation precision"
            value={pct(card.escalation_precision)}
            note="when it asked for a human, was that right"
          />
          <Metric
            label="Escalation recall"
            value={pct(card.escalation_recall)}
            note="of the ones it should have escalated"
          />
          <Metric
            label="Injection attempts caught"
            value={`${card.injection_caught}/${card.injection_total}`}
            highlight
          />
          <Metric
            label="Escalated as an IOC"
            value={`${card.injection_escalated_as_ioc}/${card.injection_total}`}
            note="caught is not enough — it has to be reported"
          />
        </div>

        <h3 className="mb-2 mt-4 text-[11px] font-semibold uppercase tracking-wide muted">
          ATT&CK, cost and latency
        </h3>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Technique recall" value={pct(card.technique_recall)} />
          <Metric
            label="Invalid technique IDs emitted"
            value={String(card.invalid_techniques_emitted)}
            note="validated against the bundle; anything above zero is a bug"
          />
          <Metric
            label="Median time to triage"
            value={`${(card.median_triage_ms / 1000).toFixed(2)}s`}
          />
          <Metric
            label="Cost per alert"
            value={`$${card.usd_per_alert.toFixed(6)}`}
            note={card.provider === "mock" ? "zero because no request was made" : undefined}
          />
        </div>
      </Panel>

      <Panel title="Per-alert outcomes">
        <ul className="divide-y" style={{ borderColor: "var(--edge)" }}>
          {card.outcomes.map((outcome) => (
            <li key={outcome.alert_id} className="flex flex-wrap items-center gap-3 py-2">
              <span
                className="text-xs"
                style={{ color: outcome.correct ? "var(--color-fp)" : "var(--color-tp)" }}
              >
                {outcome.correct ? "✓" : "✗"}
              </span>
              <span className="mono w-64 shrink-0 text-xs">{outcome.alert_id}</span>
              <VerdictPill label={outcome.expected} />
              {!outcome.correct && (
                <>
                  <span className="muted text-xs">got</span>
                  <VerdictPill label={outcome.actual} confidence={outcome.confidence} />
                </>
              )}
              {outcome.missed_true_positive && (
                <span className="text-[10px] uppercase" style={{ color: "var(--color-tp)" }}>
                  missed true positive
                </span>
              )}
              {outcome.injection_expected && (
                <span
                  className="text-[10px] uppercase"
                  style={{
                    color: outcome.injection_caught
                      ? "var(--color-fp)"
                      : "var(--color-tp)",
                  }}
                >
                  injection {outcome.injection_caught ? "caught" : "missed"}
                </span>
              )}
              <span className="mono muted ml-auto text-[10px]">{outcome.duration_ms}ms</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
