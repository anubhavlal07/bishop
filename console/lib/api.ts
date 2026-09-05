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
  process.env.NEXT_PUBLIC_BISHOP_API?.replace(/\/$/, "") ??
  "http://localhost:8000";

/**
 * The API key, when the deployment has authentication on.
 *
 * `NEXT_PUBLIC_` means this is baked into the client bundle and readable by
 * anyone who opens devtools. That is acceptable only because of what the key
 * is: a shared read-and-triage credential for one deployment, rotatable from
 * the dashboard. It is not a user identity and must not be treated as one —
 * a per-user login needs a session flow the API does not have yet, and the
 * README says so rather than implying otherwise.
 */
const API_KEY = process.env.NEXT_PUBLIC_BISHOP_API_KEY ?? "";

function withAuth(init?: RequestInit): RequestInit {
  const headers = new Headers(init?.headers);
  if (API_KEY) headers.set("Authorization", `Bearer ${API_KEY}`);
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

  /** Map a submitted alert and report what Bishop understood, without running. */
  previewIngest: (alert: unknown) =>
    get<IngestPreview>("/ingest/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert }),
    }),

  /** Triage an alert the user supplied rather than one from the corpus. */
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

/**
 * The SSE URL, with the key as a query parameter.
 *
 * `EventSource` cannot send headers — that is a gap in the browser API, not a
 * choice — so the key travels in the query string for this one endpoint. It is
 * therefore visible in server access logs, which is why Bishop's own access log
 * records a fingerprint rather than the URL's query. Behind TLS it is not on
 * the wire in clear, but it is the weakest link in this scheme and is written
 * down as such.
 */
export function eventStreamUrl(runId: string): string {
  const base = `${API_BASE}/runs/${runId}/events`;
  return API_KEY ? `${base}?api_key=${encodeURIComponent(API_KEY)}` : base;
}
