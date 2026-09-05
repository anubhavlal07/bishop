/**
 * The API client.
 *
 * Every function throws `ApiError` on failure rather than returning a default.
 * That is deliberate: an empty alert list and an unreachable API look identical
 * on screen, and the second one is the analyst's problem to know about.
 */

import type {
  AlertSummary,
  AuditEntry,
  Coverage,
  DetectorSpec,
  Health,
  IngestPreview,
  MappingReport,
  RunState,
  Scorecard,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_BISHOP_API?.replace(/\/$/, "") ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function get<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { cache: "no-store", ...init });
  } catch (cause) {
    throw new ApiError(
      `Cannot reach Bishop's API at ${API_BASE}. Is it running? Start it with \`just api\`.`,
    );
  }
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApiError(
      `${path} returned ${response.status}${body ? `: ${body.slice(0, 200)}` : ""}`,
      response.status,
    );
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => get<Health>("/health"),

  alerts: () => get<{ count: number; alerts: AlertSummary[] }>("/alerts"),

  detectors: () =>
    get<{ count: number; surfaces: string[]; detectors: DetectorSpec[] }>("/detectors"),

  coverage: () => get<Coverage>("/coverage"),

  scorecard: () => get<Scorecard>("/scorecard"),

  run: (runId: string) => get<RunState>(`/runs/${runId}`),

  audit: (runId: string) =>
    get<{ run_id: string; intact: boolean; entries: AuditEntry[] }>(`/runs/${runId}/audit`),

  startRun: (alertId: string) =>
    get<{ run_id: string; status: string }>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId }),
    }),

  /** Map a submitted alert and report what Bishop understood, without running. */
  previewIngest: (alert: unknown) =>
    get<IngestPreview>("/ingest/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    }),

  /** Triage an alert the user supplied rather than one from the corpus. */
  startRunFromAlert: (alert: unknown) =>
    get<{ run_id: string; status: string; alert_id: string; mapping: MappingReport }>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    }),

  ingestFormats: () => get<{ formats: Record<string, string> }>("/ingest/formats"),

  decide: (
    runId: string,
    body: {
      decision: "approved" | "rejected" | "modified";
      approved_action_ids: string[];
      decided_by: string;
      note?: string;
    },
  ) =>
    get<{ run_id: string; status: string }>(`/runs/${runId}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: "", ...body }),
    }),
};

export function eventStreamUrl(runId: string): string {
  return `${API_BASE}/runs/${runId}/events`;
}
