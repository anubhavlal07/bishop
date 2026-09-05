/**
 * The viewer's own model credentials, kept in their browser.
 *
 * Bishop's server stores no model key. Each person supplies their own, it lives
 * in `localStorage` on this origin, and it travels as a header on the requests
 * that need it. The server builds a provider from it for the duration of one
 * run and drops it.
 *
 * **Be honest about what that costs.** `localStorage` is readable by any script
 * running on this origin, so an XSS bug in this console is a key-theft bug.
 * That is stated in the setup dialog rather than buried here. It buys something
 * real in exchange: the deployment holds no secret to leak or rotate, nobody's
 * spend is anybody else's, and a compromise of the API yields no key.
 *
 * Every accessor below tolerates storage being unavailable — private windows,
 * cleared site data, and browsers configured to block storage all throw on
 * access rather than returning null.
 */

const STORAGE_KEY = "bishop.model.credentials.v1";

export interface StoredCredentials {
  provider: string;
  apiKey: string;
  modelId: string;
  endpoint?: string;
  /** When the key was last confirmed to work, so the UI can say "verified". */
  verifiedAt?: string;
}

export interface ProviderInfo {
  key: string;
  label: string;
  default_model: string;
  models: string[];
  key_hint: string;
  needs_endpoint: boolean;
  help_url: string;
}

export function loadCredentials(): StoredCredentials | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredCredentials;
    if (!parsed?.provider) return null;
    return parsed;
  } catch {
    // A corrupt or unreadable value is the same as none: the setup dialog opens.
    return null;
  }
}

export function saveCredentials(credentials: StoredCredentials): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
    window.dispatchEvent(new Event("bishop:credentials"));
  } catch {
    // Nothing useful to do. The caller shows the failure; silently pretending
    // it saved would be worse than the run failing later with a clear message.
  }
}

export function clearCredentials(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event("bishop:credentials"));
  } catch {
    /* see above */
  }
}

/**
 * The headers that carry the key to the API.
 *
 * Headers rather than the request body: a body is the thing most likely to be
 * logged by a proxy or echoed back in an error message.
 */
export function credentialHeaders(): Record<string, string> {
  const stored = loadCredentials();
  if (!stored || stored.provider === "mock") return {};
  const headers: Record<string, string> = {
    "X-Model-Provider": stored.provider,
    "X-Model-Key": stored.apiKey,
  };
  if (stored.modelId) headers["X-Model-Id"] = stored.modelId;
  if (stored.endpoint) headers["X-Model-Endpoint"] = stored.endpoint;
  return headers;
}

/** Whether the viewer has made a choice at all — drives the first-run dialog. */
export function hasChosen(): boolean {
  return loadCredentials() !== null;
}

/** Last four characters, for showing which key is configured without showing it. */
export function keyTail(apiKey: string): string {
  return apiKey.length <= 4 ? "••••" : `••••${apiKey.slice(-4)}`;
}
