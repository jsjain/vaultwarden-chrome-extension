import type { AuthSession } from "./storage";

const DATABASE_NAME = "leanvault-session";
const DATABASE_VERSION = 1;
const STORE = "records";
const DEVICE_KEY_ID = "device-key";
const SESSION_ID = "auth-session";
const ADDITIONAL_DATA = new TextEncoder().encode("leanvault-persistent-session-v1");

interface DeviceKeyRecord {
  id: typeof DEVICE_KEY_ID;
  key: CryptoKey;
}

interface EncryptedSessionRecord {
  id: typeof SESSION_ID;
  iv: number[];
  ciphertext: number[];
}

export async function writePersistentAuthSession(session: AuthSession): Promise<void> {
  const key = await getOrCreateDeviceKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(session));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: ADDITIONAL_DATA },
      key,
      plaintext,
    );
    await putRecord({ id: SESSION_ID, iv: [...iv], ciphertext: [...new Uint8Array(ciphertext)] });
  } finally {
    plaintext.fill(0);
  }
}

export async function readPersistentAuthSession(): Promise<AuthSession | null> {
  const [keyRecord, sessionRecord] = await Promise.all([
    getRecord<DeviceKeyRecord>(DEVICE_KEY_ID),
    getRecord<EncryptedSessionRecord>(SESSION_ID),
  ]);
  if (!keyRecord || !sessionRecord) return null;
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(sessionRecord.iv),
        additionalData: ADDITIONAL_DATA,
      },
      keyRecord.key,
      new Uint8Array(sessionRecord.ciphertext),
    ),
  );
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    return isAuthSession(value) ? value : null;
  } finally {
    plaintext.fill(0);
  }
}

export async function clearPersistentAuthSession(): Promise<void> {
  const database = await openDatabase();
  try {
    await transactionPromise(
      database.transaction(STORE, "readwrite").objectStore(STORE).delete(SESSION_ID),
    );
  } finally {
    database.close();
  }
}

async function getOrCreateDeviceKey(): Promise<CryptoKey> {
  const existing = await getRecord<DeviceKeyRecord>(DEVICE_KEY_ID);
  if (existing) return existing.key;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  await putRecord({ id: DEVICE_KEY_ID, key } satisfies DeviceKeyRecord);
  return key;
}

async function getRecord<T>(id: string): Promise<T | null> {
  const database = await openDatabase();
  try {
    const value = await transactionPromise<T | undefined>(
      database.transaction(STORE, "readonly").objectStore(STORE).get(id),
    );
    return value ?? null;
  } finally {
    database.close();
  }
}

async function putRecord(record: DeviceKeyRecord | EncryptedSessionRecord): Promise<void> {
  const database = await openDatabase();
  try {
    await transactionPromise(
      database.transaction(STORE, "readwrite").objectStore(STORE).put(record),
    );
  } finally {
    database.close();
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("The persistent session database could not be opened."));
    request.onblocked = () => reject(new Error("The persistent session database upgrade was blocked."));
  });
}

function transactionPromise<T = undefined>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("The persistent session database operation failed."));
  });
}

function isAuthSession(value: unknown): value is AuthSession {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const session = value as Record<string, unknown>;
  return (
    typeof session.baseUrl === "string" &&
    typeof session.email === "string" &&
    typeof session.accessToken === "string" &&
    (session.refreshToken === undefined || typeof session.refreshToken === "string") &&
    (session.accessTokenExpiresAt === undefined || typeof session.accessTokenExpiresAt === "number") &&
    (session.userKey === undefined ||
      (Array.isArray(session.userKey) &&
        session.userKey.length === 64 &&
        session.userKey.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)))
  );
}
