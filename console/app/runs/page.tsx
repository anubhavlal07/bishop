"use client";

/**
 * One run, read from `?id=`.
 *
 * A query parameter rather than a path segment (`/runs/[runId]`) so the console
 * is a fully static export. A run id is created at request time and cannot be
 * known at build time, so a dynamic path segment forces a server to render it —
 * and the console does not need a server for anything else. Every page here is
 * a client component that talks to Bishop's API directly, so making the last
 * route static turns the whole thing into files on a CDN.
 */

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { Panel } from "@/components/primitives";
import { RunDetail } from "@/components/RunDetail";

function Run() {
  const runId = useSearchParams().get("id");

  if (!runId) {
    return (
      <Panel title="No run selected" subtitle="open one from the alert queue">
        <p className="muted text-xs leading-relaxed">
          This page shows one triage run. Start one from the alert queue, or paste an alert of
          your own on the Triage page.
        </p>
      </Panel>
    );
  }
  return <RunDetail runId={runId} />;
}

export default function RunPage() {
  // `useSearchParams` suspends during prerender, so the boundary is required
  // for a static build rather than optional.
  return (
    <Suspense fallback={<p className="muted text-xs">Loading the run…</p>}>
      <Run />
    </Suspense>
  );
}
