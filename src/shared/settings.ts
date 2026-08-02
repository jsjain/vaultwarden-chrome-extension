export const VAULT_TIMEOUT_OPTIONS = [-1, 0, 15, 60, 240] as const;

export type VaultTimeoutMinutes = (typeof VAULT_TIMEOUT_OPTIONS)[number];

const VAULT_TIMEOUT_KEY = "leanvault.vaultTimeoutMinutes";
const DEFAULT_VAULT_TIMEOUT: VaultTimeoutMinutes = 0;

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
