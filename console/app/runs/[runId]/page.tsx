"use client";

import { use } from "react";

import { RunDetail } from "@/components/RunDetail";

export default function RunPage({ params }: { params: Promise<{ runId: string }> }) {
  const { runId } = use(params);
  return <RunDetail runId={runId} />;
}
