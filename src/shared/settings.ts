export const VAULT_TIMEOUT_OPTIONS = [-1, 0, 15, 60, 240] as const;

export type VaultTimeoutMinutes = (typeof VAULT_TIMEOUT_OPTIONS)[number];

export interface BrowserIntegrationOptions {
  askAddLogin: boolean;
  askUpdateLogin: boolean;
  excludedDomains: string[];
}

export interface StoredGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const VAULT_TIMEOUT_KEY = "leanvault.vaultTimeoutMinutes";
const DEFAULT_VAULT_TIMEOUT: VaultTimeoutMinutes = 0;
const BROWSER_OPTIONS_KEY = "leanvault.browserIntegrationOptions";
const GENERATOR_OPTIONS_KEY = "leanvault.generatorOptions";

export const DEFAULT_BROWSER_INTEGRATION_OPTIONS: BrowserIntegrationOptions = {
  askAddLogin: true,
  askUpdateLogin: true,
  excludedDomains: [],
};

export const DEFAULT_GENERATOR_OPTIONS: StoredGeneratorOptions = {
  length: 22,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

export async function readVaultTimeoutMinutes(): Promise<VaultTimeoutMinutes> {
  const value = await chrome.storage.local.get(VAULT_TIMEOUT_KEY);
  const minutes = value[VAULT_TIMEOUT_KEY];
  return isVaultTimeoutMinutes(minutes) ? minutes : DEFAULT_VAULT_TIMEOUT;
}

export async function writeVaultTimeoutMinutes(minutes: VaultTimeoutMinutes): Promise<void> {
  await chrome.storage.local.set({ [VAULT_TIMEOUT_KEY]: minutes });
}

export function isVaultTimeoutMinutes(value: unknown): value is VaultTimeoutMinutes {
  return VAULT_TIMEOUT_OPTIONS.some((minutes) => minutes === value);
}

export async function readBrowserIntegrationOptions(): Promise<BrowserIntegrationOptions> {
  const value = await chrome.storage.local.get(BROWSER_OPTIONS_KEY);
  return normalizeBrowserIntegrationOptions(value[BROWSER_OPTIONS_KEY]);
}

export async function writeBrowserIntegrationOptions(options: BrowserIntegrationOptions): Promise<void> {
  await chrome.storage.local.set({ [BROWSER_OPTIONS_KEY]: normalizeBrowserIntegrationOptions(options) });
}

export function normalizeBrowserIntegrationOptions(value: unknown): BrowserIntegrationOptions {
  if (!isRecord(value)) return { ...DEFAULT_BROWSER_INTEGRATION_OPTIONS };
  const excludedDomains = Array.isArray(value.excludedDomains)
    ? [...new Set(value.excludedDomains.filter((domain): domain is string => typeof domain === "string")
      .map(normalizeDomain).filter(Boolean))].slice(0, 200)
    : [];
  return {
    askAddLogin: typeof value.askAddLogin === "boolean" ? value.askAddLogin : true,
    askUpdateLogin: typeof value.askUpdateLogin === "boolean" ? value.askUpdateLogin : true,
    excludedDomains,
  };
}

export function isBrowserIntegrationOptions(value: unknown): value is BrowserIntegrationOptions {
  if (!isRecord(value) || typeof value.askAddLogin !== "boolean" || typeof value.askUpdateLogin !== "boolean") return false;
  return Array.isArray(value.excludedDomains) && value.excludedDomains.length <= 200 &&
    value.excludedDomains.every((domain) => typeof domain === "string" && domain.length > 0 && domain.length <= 253);
}

export function isUrlExcluded(url: string, options: BrowserIntegrationOptions): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return true;
  }
  return options.excludedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

export async function readGeneratorOptions(): Promise<StoredGeneratorOptions> {
  const value = await chrome.storage.local.get(GENERATOR_OPTIONS_KEY);
  return normalizeGeneratorOptions(value[GENERATOR_OPTIONS_KEY]);
}

export async function writeGeneratorOptions(options: StoredGeneratorOptions): Promise<void> {
  await chrome.storage.local.set({ [GENERATOR_OPTIONS_KEY]: normalizeGeneratorOptions(options) });
}

export function normalizeGeneratorOptions(value: unknown): StoredGeneratorOptions {
  if (!isRecord(value)) return { ...DEFAULT_GENERATOR_OPTIONS };
  const length = Number.isSafeInteger(value.length) && Number(value.length) >= 8 && Number(value.length) <= 64
    ? Number(value.length)
    : DEFAULT_GENERATOR_OPTIONS.length;
  const option = (name: keyof Omit<StoredGeneratorOptions, "length">): boolean =>
    typeof value[name] === "boolean" ? value[name] as boolean : DEFAULT_GENERATOR_OPTIONS[name];
  const result = { length, uppercase: option("uppercase"), lowercase: option("lowercase"), numbers: option("numbers"), symbols: option("symbols") };
  return result.uppercase || result.lowercase || result.numbers || result.symbols
    ? result
    : { ...DEFAULT_GENERATOR_OPTIONS };
}

export function isGeneratorOptions(value: unknown): value is StoredGeneratorOptions {
  return isRecord(value) && Number.isSafeInteger(value.length) && Number(value.length) >= 8 && Number(value.length) <= 64 &&
    ["uppercase", "lowercase", "numbers", "symbols"].every((name) => typeof value[name] === "boolean") &&
    Boolean(value.uppercase || value.lowercase || value.numbers || value.symbols);
}

function normalizeDomain(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
