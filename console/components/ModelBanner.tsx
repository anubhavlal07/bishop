"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Health } from "@/lib/types";

export function ModelBanner() {
  const [health, setHealth] = useState<Health | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  if (!health?.live || health.live.ready) return null;
  const live = health.live;

  return (
    <div
      className="rounded border p-3 text-xs leading-relaxed"
      style={{ borderColor: "var(--edge)", background: "var(--panel)" }}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span style={{ color: "var(--color-escalate)" }}>
          Running on the deterministic model.
        </span>
        <button onClick={() => setOpen(!open)} className="muted underline">
          {open ? "hide detail" : "what does that change?"}
        </button>
      </div>

      {open && (
        <div className="mt-2 space-y-3">
          <p className="muted">{live.what_mock_still_does}</p>

          <div>
            <div className="mb-1">To run against Claude instead:</div>
            <ol className="mono muted space-y-0.5">
              {live.missing.map((step) => (
                <li key={step}>$ {step}</li>
              ))}
              <li>$ just api</li>
            </ol>
          </div>

          <p className="muted">
            A live run costs real money and Bishop refuses to start one without
            a key rather than silently falling back — a scorecard that quietly
            changed provider would be meaningless.
          </p>
        </div>
      )}
    </div>
  );
}
