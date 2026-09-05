import { credentialHeaders } from "./credentials";
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

/**
 * Where the API lives.
 *
 * `NEXT_PUBLIC_BISHOP_API` overrides it, which is what a fork or a local build
 * against a different backend uses. Absent that, the default depends on the
 * build: a production build points at the deployed API, a development build at
 * localhost.
 *
 * The fallback is deliberate rather than lazy. A deployed console whose
 * default is `localhost:8000` looks perfectly healthy and fails for every
 * visitor, because the one machine where it works is the one that built it.
 */
export const PRODUCTION_API = "https://api.bishop.anubhavlal.dev";

export const API_BASE =
  process.env.NEXT_PUBLIC_BISHOP_API?.replace(/\/$/, "") ??
  (process.env.NODE_ENV === "production" ? PRODUCTION_API : "http://localhost:8000");

const API_KEY = process.env.NEXT_PUBLIC_BISHOP_API_KEY ?? "";

function withAuth(init?: RequestInit): RequestInit {
  const headers = new Headers(init?.headers);
  if (API_KEY) headers.set("Authorization", `Bearer ${API_KEY}`);

  for (const [name, value] of Object.entries(credentialHeaders())) {
    headers.set(name, value);
  }
  return { ...init, headers };
}

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
    response = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      ...withAuth(init),
    });
  } catch (cause) {
    throw new ApiError(
      `Cannot reach Bishop's API at ${API_BASE}. Is it running? Start it with \`just api\`.`,
    );
  }
  if (response.status === 401) {
    throw new ApiError(
      API_KEY
        ? "The API rejected this console's key. It may have been rotated — check NEXT_PUBLIC_BISHOP_API_KEY."
        : "This Bishop requires an API key and the console has none. Set NEXT_PUBLIC_BISHOP_API_KEY and rebuild.",
      401,
    );
  }
  if (response.status === 429) {
    throw new ApiError(
      "Rate limited by the API. Wait a minute and try again.",
      429,
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
    get<{ count: number; surfaces: string[]; detectors: DetectorSpec[] }>(
      "/detectors",
    ),

  coverage: () => get<Coverage>("/coverage"),

  scorecard: () => get<Scorecard>("/scorecard"),

  run: (runId: string) => get<RunState>(`/runs/${runId}`),

  audit: (runId: string) =>
    get<{ run_id: string; intact: boolean; entries: AuditEntry[] }>(
      `/runs/${runId}/audit`,
    ),

  startRun: (alertId: string) =>
    get<{ run_id: string; status: string }>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId }),
    }),

  previewIngest: (alert: unknown) =>
    get<IngestPreview>("/ingest/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    }),

  startRunFromAlert: (alert: unknown) =>
    get<{
      run_id: string;
      status: string;
      alert_id: string;
      mapping: MappingReport;
    }>("/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    }),

  ingestFormats: () =>
    get<{ formats: Record<string, string> }>("/ingest/formats"),

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
  const base = `${API_BASE}/runs/${runId}/events`;
  return API_KEY ? `${base}?api_key=${encodeURIComponent(API_KEY)}` : base;
}
