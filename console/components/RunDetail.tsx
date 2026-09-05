"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { AuditEntry, ExecutionRecord, Incident } from "@/lib/types";
import { useRunStream } from "@/lib/useRunStream";
import { ApprovalModal } from "./ApprovalModal";
import { EvidencePanel } from "./EvidencePanel";
import { Topology } from "./Topology";
import { ApiDown, Empty, Panel, VerdictPill } from "./primitives";

function ExecutionLog({ log }: { log: ExecutionRecord[] }) {
  if (log.length === 0) return <Empty>Nothing has executed.</Empty>;
  return (
    <ul className="space-y-1.5">
      {log.map((record) => {
        const refused = record.status === "refused";
        const colour = refused ? "var(--color-escalate)" : "var(--color-fp)";
        return (
          <li key={record.action_id} className="text-xs">
            <span
              className="mono rounded px-1.5 py-0.5 text-[10px] uppercase"
              style={{ color: colour, border: `1px solid ${colour}` }}
            >
              {refused ? "refused" : "simulated"}
            </span>
            <span className="mono ml-2">{record.action_type}</span>
            <span className="muted"> → {record.target}</span>
            <p className="muted mt-0.5 pl-1 leading-relaxed">
              {record.reason ?? record.detail}
            </p>
          </li>
        );
      })}
    </ul>
  );
}

function AuditPanel({ runId, entries }: { runId: string; entries: number }) {
  const [rows, setRows] = useState<AuditEntry[] | null>(null);
  const [intact, setIntact] = useState<boolean | null>(null);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || rows) return;
    void (async () => {
      try {
        const result = await api.audit(runId);
        setRows(result.entries);
        setIntact(result.intact);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
  }, [open, rows, runId]);

  return (
    <Panel
      title="Audit chain"
      subtitle={`${entries} entries`}
      right={
        <button
          type="button"
          className="text-xs muted underline"
          onClick={() => setOpen((v) => !v)}
        >
          {open ? "hide" : "show"}
        </button>
      }
    >
      {intact !== null && (
        <p
          className="mb-2 text-xs"
          style={{ color: intact ? "var(--color-fp)" : "var(--color-tp)" }}
        >
          {intact
            ? "Chain verifies — every entry hashes to the one after it."
            : "Chain does not verify. Something was rewritten."}
        </p>
      )}
      {error && (
        <p className="text-xs" style={{ color: "var(--color-tp)" }}>
          {error}
        </p>
      )}
      {open && rows && (
        <ol className="max-h-80 space-y-1 overflow-auto">
          {rows.map((entry) => (
            <li key={entry.entry_hash} className="mono text-[11px]">
              <span className="muted">
                {String(entry.seq).padStart(3, "0")}
              </span>{" "}
              <span style={{ color: "var(--color-btp)" }}>{entry.action}</span>{" "}
              <span className="muted">{entry.actor}</span>{" "}
              <span className="muted opacity-60">
                {entry.entry_hash.slice(0, 12)}…
              </span>
            </li>
          ))}
        </ol>
      )}
      {!open && (
        <p className="muted text-xs">
          Every step, model call, evidence artefact and human decision, chained.
          A correction is a new entry, never an edit.
        </p>
      )}
    </Panel>
  );
}

function Timeline({
  events,
}: {
  events: Array<{ kind: string; at?: string }>;
}) {
  if (events.length === 0) return <Empty>Waiting for the first event.</Empty>;
  return (
    <ol className="max-h-72 space-y-1 overflow-auto">
      {events.map((event, index) => (
        <li key={`${event.kind}-${index}`} className="text-[11px]">
          <span className="mono muted">
            {event.at?.slice(11, 19) ?? "--:--:--"}
          </span>{" "}
          <span
            style={{
              color:
                event.kind === "injection_detected"
                  ? "var(--color-injection)"
                  : event.kind === "failed"
                    ? "var(--color-tp)"
                    : undefined,
            }}
          >
            {event.kind}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function RunDetail({ runId }: { runId: string }) {
  const { events, state, error, resubscribe } = useRunStream(runId);
  const [decided, setDecided] = useState(false);

  const incident: Incident | null = state?.incident ?? null;
  const verdict = incident?.verdict ?? null;
  const showGate =
    state?.status === "awaiting_approval" && state.approval_request && !decided;

  if (error && !state) return <ApiDown message={error} />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">{state?.alert_id ?? runId}</h1>
        <VerdictPill
          label={verdict?.label ?? null}
          confidence={verdict?.confidence}
        />
        <span className="muted text-xs">
          {state?.status === "awaiting_approval"
            ? "paused — waiting for a human"
            : (state?.status ?? "starting")}
        </span>
        {incident?.cost && (
          <span className="mono ml-auto text-[11px] muted">
            {incident.cost.model_calls} model calls ·{" "}
            {incident.cost.input_tokens + incident.cost.output_tokens} tokens ·
            ${incident.cost.usd.toFixed(6)}
          </span>
        )}
      </div>

      {state?.error && (
        <div
          className="panel p-3 text-xs"
          style={{ borderColor: "var(--color-tp)", color: "var(--color-tp)" }}
        >
          {state.error}
        </div>
      )}

      <Panel title="Agent graph" subtitle="investigators run in parallel">
        <Topology events={events} />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {verdict && (
            <Panel title="Verdict">
              <p className="text-xs leading-relaxed">{verdict.rationale}</p>
              {verdict.escalation_reason && (
                <p
                  className="mt-2 rounded px-3 py-2 text-xs leading-relaxed"
                  style={{
                    color: "var(--color-escalate)",
                    border: "1px solid var(--color-escalate)",
                    background: "var(--color-escalate)0f",
                  }}
                >
                  Escalated: {verdict.escalation_reason}
                </p>
              )}
              {verdict.narrative && (
                <>
                  <h3 className="mt-3 text-xs font-medium uppercase tracking-wide muted">
                    Attack narrative
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed">
                    {verdict.narrative}
                  </p>
                </>
              )}
              {verdict.technique_ids.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {verdict.technique_ids.map((id) => (
                    <a
                      key={id}
                      href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="mono rounded px-1.5 py-0.5 text-[11px]"
                      style={{
                        border: "1px solid var(--edge)",
                        color: "var(--color-btp)",
                      }}
                    >
                      {id}
                    </a>
                  ))}
                </div>
              )}
              {verdict.counter_arguments.length > 0 && (
                <>
                  <h3 className="mt-3 text-xs font-medium uppercase tracking-wide muted">
                    What would make this wrong
                  </h3>
                  <ul className="mt-1 list-disc space-y-1 pl-4">
                    {verdict.counter_arguments.map((argument) => (
                      <li
                        key={argument}
                        className="muted text-xs leading-relaxed"
                      >
                        {argument}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </Panel>
          )}

          <Panel title="Evidence">
            <EvidencePanel reports={incident?.reports ?? []} />
          </Panel>

          {incident?.response_plan && (
            <Panel title="Proposed response">
              {incident.response_plan.actions.length > 0 ? (
                <>
                  {/* "Proposed" and not "performed": after a modified decision
                      the execution log below shows fewer actions than this
                      sentence names, and the distinction is the whole point of
                      the gate. Labelled rather than left to be inferred. */}
                  <p className="text-xs font-medium leading-relaxed">
                    {incident.response_plan.proposes}
                  </p>
                  <p className="muted mt-2 text-xs leading-relaxed">
                    {incident.response_plan.strategy}
                  </p>
                  <ExecutionLog log={incident.execution_log} />
                </>
              ) : (
                <p className="muted text-xs leading-relaxed">
                  {incident.response_plan.no_action_rationale ??
                    incident.response_plan.strategy}
                </p>
              )}
              {incident.human_decision &&
                incident.human_decision.decided_by !== "system" && (
                  <p className="muted mt-3 text-[11px]">
                    {incident.human_decision.decision} by{" "}
                    {incident.human_decision.decided_by}
                    {incident.human_decision.note &&
                      ` — ${incident.human_decision.note}`}
                  </p>
                )}
            </Panel>
          )}
        </div>

        <div className="space-y-4">
          <Panel title="Timeline">
            <Timeline events={events} />
          </Panel>
          <AuditPanel runId={runId} entries={state?.audit_entries ?? 0} />
        </div>
      </div>

      {showGate && state?.approval_request && (
        <ApprovalModal
          request={state.approval_request}
          onDecide={async (body) => {
            await api.decide(runId, body);
            setDecided(true);

            resubscribe();
          }}
        />
      )}
    </div>
  );
}
