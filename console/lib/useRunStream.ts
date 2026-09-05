"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api, eventStreamUrl } from "./api";
import type { RunEvent, RunState } from "./types";

interface UseRunStream {
  events: RunEvent[];
  state: RunState | null;
  error: string | null;
  connected: boolean;
  resubscribe: () => void;
}

export function useRunStream(runId: string | null): UseRunStream {
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [state, setState] = useState<RunState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const sourceRef = useRef<EventSource | null>(null);

  const resubscribe = useCallback(() => setEpoch((n) => n + 1), []);

  const refreshState = useCallback(async () => {
    if (!runId) return;
    try {
      setState(await api.run(runId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [runId]);

  useEffect(() => {
    if (!runId) return;

    setEvents([]);
    setError(null);

    const source = new EventSource(eventStreamUrl(runId));
    sourceRef.current = source;

    const handle = (event: MessageEvent<string>) => {
      setConnected(true);
      let payload: RunEvent;
      try {
        payload = JSON.parse(event.data) as RunEvent;
      } catch {
        return;
      }
      if (payload.kind === "heartbeat") return;
      setEvents((current) => [...current, payload]);

      if (["awaiting_approval", "done", "failed"].includes(payload.kind)) {
        void refreshState();
        source.close();
        setConnected(false);
      }
    };

    const kinds = [
      "started",
      "continued",
      "resumed",
      "ingested",
      "injection_detected",
      "dispatched",
      "detectors_ran",
      "investigator_reported",
      "techniques_rejected",
      "verdict",
      "critique",
      "response_planned",
      "approval_requested",
      "human_decided",
      "action_executed",
      "action_refused",
      "completed",
      "awaiting_approval",
      "done",
      "failed",
      "heartbeat",
      "message",
    ];
    for (const kind of kinds)
      source.addEventListener(kind, handle as EventListener);

    source.onerror = () => {
      setConnected(false);
      void refreshState();
    };

    void refreshState();

    return () => {
      for (const kind of kinds)
        source.removeEventListener(kind, handle as EventListener);
      source.close();
      sourceRef.current = null;
    };
  }, [runId, epoch, refreshState]);

  return { events, state, error, connected, resubscribe };
}
