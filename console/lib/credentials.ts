const STORAGE_KEY = "bishop.model.credentials.v1";

export interface StoredCredentials {
  provider: string;
  apiKey: string;
  modelId: string;
  endpoint?: string;

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
    return null;
  }
}

export function saveCredentials(credentials: StoredCredentials): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
    window.dispatchEvent(new Event("bishop:credentials"));
  } catch {}
}

export function clearCredentials(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event("bishop:credentials"));
  } catch {}
}

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

export function hasChosen(): boolean {
  return loadCredentials() !== null;
}

export function keyTail(apiKey: string): string {
  return apiKey.length <= 4 ? "••••" : `••••${apiKey.slice(-4)}`;
}
