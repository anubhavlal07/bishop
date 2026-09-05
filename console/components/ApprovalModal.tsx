"use client";

import { useMemo, useState } from "react";

import type { ApprovalRequest } from "@/lib/types";
import { VerdictPill } from "./primitives";

interface Props {
  request: ApprovalRequest;
  onDecide: (body: {
    decision: "approved" | "rejected" | "modified";
    approved_action_ids: string[];
    decided_by: string;
    note: string;
  }) => Promise<void>;
}

export function ApprovalModal({ request, onDecide }: Props) {
  const reversibleIds = useMemo(
    () =>
      request.actions.filter((a) => !a.irreversible).map((a) => a.action_id),
    [request.actions],
  );
  const [selected, setSelected] = useState<string[]>(reversibleIds);
  const [who, setWho] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = (id: string) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((x) => x !== id) : [...current, id],
    );

  const submit = async (decision: "approved" | "rejected" | "modified") => {
    setBusy(true);
    setError(null);
    try {
      const ids =
        decision === "rejected"
          ? []
          : decision === "approved"
            ? request.actions.map((a) => a.action_id)
            : selected;
      await onDecide({
        decision,
        approved_action_ids: ids,
        decided_by: who.trim() || "console (unnamed)",
        note,
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setBusy(false);
    }
  };

  const allSelected = selected.length === request.actions.length;
  const noneSelected = selected.length === 0;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/70 p-6">
      <div className="panel w-full max-w-3xl">
        <header
          className="border-b px-5 py-4"
          style={{ borderColor: "var(--edge)" }}
        >
          <div className="flex items-center gap-3">
            <h2
              className="text-base font-semibold"
              style={{ color: "var(--color-escalate)" }}
            >
              Bishop is waiting for you
            </h2>
            <VerdictPill
              label={request.verdict.label}
              confidence={request.verdict.confidence}
            />
          </div>
          <p className="muted mt-2 text-xs leading-relaxed">
            {request.verdict.rationale}
          </p>
          {request.verdict.counter_arguments.length > 0 && (
            <details className="mt-2">
              <summary
                className="cursor-pointer text-xs"
                style={{ color: "var(--color-escalate)" }}
              >
                What would make this verdict wrong (
                {request.verdict.counter_arguments.length})
              </summary>
              <ul className="mt-1 list-disc space-y-1 pl-5">
                {request.verdict.counter_arguments.map((argument) => (
                  <li key={argument} className="muted text-xs leading-relaxed">
                    {argument}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </header>

        <div className="px-5 py-4">
          {/* `proposes` is computed from the plan's action list; `strategy` is
              what the model wrote about it. Shown separately, and in that
              order, because the first cannot disagree with the *proposal* and
              the second can — a plan once claimed to contain a host and an
              account while proposing only a ticket. Showing both lets the
              analyst see that disagreement rather than trusting whichever one
              Bishop decided to keep.

              It describes the proposal, not the current selection: untick two
              of three isolations and this line still counts three, while the
              footer counts what is actually approved. That is the honest split
              — this sentence is about what Bishop asked for. */}
          <p className="text-xs font-medium leading-relaxed">{request.proposes}</p>
          <p className="muted mt-2 text-xs leading-relaxed">{request.strategy}</p>

          <ul className="mt-4 space-y-2">
            {request.actions.map((action) => {
              const checked = selected.includes(action.action_id);
              return (
                <li
                  key={action.action_id}
                  className="rounded border px-3 py-2.5"
                  style={{
                    borderColor: action.irreversible
                      ? "var(--color-tp)"
                      : "var(--edge)",
                    background: checked ? "var(--edge)" : "transparent",
                  }}
                >
                  <label className="flex cursor-pointer items-start gap-3">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(action.action_id)}
                      className="mt-1"
                    />
                    <span className="flex-1">
                      <span className="flex flex-wrap items-baseline gap-2">
                        <span className="mono text-sm">
                          {action.action_type}
                        </span>
                        <span className="muted text-xs">→</span>
                        <span className="text-sm font-medium">
                          {action.target}
                        </span>
                        {action.irreversible && (
                          <span
                            className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                            style={{
                              color: "var(--color-tp)",
                              border: "1px solid var(--color-tp)",
                            }}
                          >
                            irreversible
                          </span>
                        )}
                      </span>
                      <p className="muted mt-1 text-xs leading-relaxed">
                        {action.rationale}
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed">
                        <span className="muted">Blast radius: </span>
                        {action.blast_radius.summary}
                      </p>
                      {action.rollback && (
                        <p className="muted mt-0.5 text-[11px] leading-relaxed">
                          Rollback: {action.rollback}
                        </p>
                      )}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>

          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            <input
              value={who}
              onChange={(e) => setWho(e.target.value)}
              placeholder="Your name — this goes in the audit chain"
              className="rounded border px-2 py-1.5 text-xs"
              style={{
                borderColor: "var(--edge)",
                background: "var(--bg)",
                color: "var(--text)",
              }}
            />
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Note (optional)"
              className="rounded border px-2 py-1.5 text-xs"
              style={{
                borderColor: "var(--edge)",
                background: "var(--bg)",
                color: "var(--text)",
              }}
            />
          </div>

          {error && (
            <p className="mt-3 text-xs" style={{ color: "var(--color-tp)" }}>
              {error}
            </p>
          )}
        </div>

        <footer
          className="flex flex-wrap items-center gap-2 border-t px-5 py-3"
          style={{ borderColor: "var(--edge)" }}
        >
          <button
            type="button"
            disabled={busy}
            onClick={() => void submit("rejected")}
            className="rounded px-3 py-1.5 text-xs"
            style={{ border: "1px solid var(--edge)" }}
          >
            Reject everything
          </button>
          <button
            type="button"
            disabled={busy || noneSelected}
            onClick={() => void submit("modified")}
            className="rounded px-3 py-1.5 text-xs disabled:opacity-40"
            style={{
              border: "1px solid var(--color-btp)",
              color: "var(--color-btp)",
            }}
          >
            Approve {selected.length} of {request.actions.length}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void submit("approved")}
            className="rounded px-3 py-1.5 text-xs"
            style={{
              border: "1px solid var(--color-tp)",
              color: "var(--color-tp)",
            }}
          >
            Approve all{allSelected ? "" : ", including irreversible"}
          </button>
          <span className="muted ml-auto text-[10px]">
            Nothing executes for real — the executor is mocked.
          </span>
        </footer>
      </div>
    </div>
  );
}
