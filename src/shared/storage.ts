import type { ServerSnapshot } from "./storage-types";
import type { KdfConfig } from "./kdf";
import {
  clearPersistentAuthSession,
  readPersistentAuthSession,
  writePersistentAuthSession,
} from "./persistent-session";
import { readVaultTimeoutMinutes } from "./settings";

const SERVER_SNAPSHOT_KEY = "serverSnapshot";
const ACCOUNT_KEY = "accountMetadata";
const DEVICE_IDENTIFIER_KEY = "deviceIdentifier";
const SESSION_KEY = "authSession";

export interface AccountMetadata {
  baseUrl: string;
  email: string;
  kdf: KdfConfig;
  wrappedUserKey: string;
  privateKey?: string;
  lastSync?: string;
  itemCount?: number;
}

export interface AuthSession {
  baseUrl: string;
  email: string;
  accessToken: string;
  refreshToken?: string;
  accessTokenExpiresAt?: number;
  userKey?: number[];
}

interface PersistedState {
  [SERVER_SNAPSHOT_KEY]?: ServerSnapshot;
  [ACCOUNT_KEY]?: AccountMetadata;
  [DEVICE_IDENTIFIER_KEY]?: string;
}

interface SessionState {
  [SESSION_KEY]?: AuthSession;
}

export async function readServerSnapshot(): Promise<ServerSnapshot | null> {
  const result = (await chrome.storage.local.get(SERVER_SNAPSHOT_KEY)) as PersistedState;
  return result[SERVER_SNAPSHOT_KEY] ?? null;
}

export async function writeServerSnapshot(snapshot: ServerSnapshot): Promise<void> {
  await chrome.storage.local.set({ [SERVER_SNAPSHOT_KEY]: snapshot });
}

export async function readAccountMetadata(): Promise<AccountMetadata | null> {
  const result = (await chrome.storage.local.get(ACCOUNT_KEY)) as PersistedState;
  return result[ACCOUNT_KEY] ?? null;
}

export async function writeAccountMetadata(account: AccountMetadata): Promise<void> {
  await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
}

export async function clearAccountMetadata(): Promise<void> {
  await chrome.storage.local.remove(ACCOUNT_KEY);
}

export async function getOrCreateDeviceIdentifier(): Promise<string> {
  const result = (await chrome.storage.local.get(DEVICE_IDENTIFIER_KEY)) as PersistedState;
  const existing = result[DEVICE_IDENTIFIER_KEY];
  if (existing) {
    return existing;
  }
  const created = crypto.randomUUID();
  await chrome.storage.local.set({ [DEVICE_IDENTIFIER_KEY]: created });
  return created;
}

export async function readAuthSession(): Promise<AuthSession | null> {
  const result = (await chrome.storage.session.get(SESSION_KEY)) as SessionState;
  const active = result[SESSION_KEY];
  if (active) return active;
  if ((await readVaultTimeoutMinutes()) !== -1) return null;
  try {
    const restored = await readPersistentAuthSession();
    if (restored) await chrome.storage.session.set({ [SESSION_KEY]: restored });
    return restored;
  } catch {
    await clearPersistentAuthSession();
    return null;
  }
}

export async function writeAuthSession(session: AuthSession): Promise<void> {
  await chrome.storage.session.set({ [SESSION_KEY]: session });
  if ((await readVaultTimeoutMinutes()) === -1) {
    await writePersistentAuthSession(session);
  } else {
    await clearPersistentAuthSession();
  }
}

export async function updateSessionUserKey(userKey: Uint8Array | null): Promise<void> {
  const session = await readAuthSession();
  if (!session) {
    throw new Error("The account session has expired. Sign in again.");
  }
  if (userKey) {
    await writeAuthSession({ ...session, userKey: [...userKey] });
  } else {
    const locked: AuthSession = { ...session };
    delete locked.userKey;
    await writeAuthSession(locked);
  }
}

export async function clearAuthSession(): Promise<void> {
  await Promise.all([chrome.storage.session.remove(SESSION_KEY), clearPersistentAuthSession()]);
}
