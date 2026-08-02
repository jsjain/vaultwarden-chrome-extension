import type { SyncResponse } from "../api/models";

const DATABASE_NAME = "leanvault";
const DATABASE_VERSION = 1;
const VAULT_STORE = "encryptedVault";
const CURRENT_RECORD = "current";

interface VaultRecord {
  id: typeof CURRENT_RECORD;
  payload: SyncResponse;
  storedAt: string;
}

export async function writeEncryptedSync(payload: SyncResponse): Promise<void> {
  const database = await openDatabase();
  try {
    await transactionPromise(
      database.transaction(VAULT_STORE, "readwrite").objectStore(VAULT_STORE).put({
        id: CURRENT_RECORD,
        payload,
        storedAt: new Date().toISOString(),
      } satisfies VaultRecord),
    );
  } finally {
    database.close();
  }
}

export async function readEncryptedSync(): Promise<SyncResponse | null> {
  const database = await openDatabase();
  try {
    const record = await transactionPromise<VaultRecord | undefined>(
      database.transaction(VAULT_STORE, "readonly").objectStore(VAULT_STORE).get(CURRENT_RECORD),
    );
    return record?.payload ?? null;
  } finally {
    database.close();
  }
}

export async function clearEncryptedSync(): Promise<void> {
  const database = await openDatabase();
  try {
    await transactionPromise(
      database.transaction(VAULT_STORE, "readwrite").objectStore(VAULT_STORE).delete(CURRENT_RECORD),
    );
  } finally {
    database.close();
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(VAULT_STORE)) {
        database.createObjectStore(VAULT_STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("The encrypted vault database could not be opened."));
    request.onblocked = () => reject(new Error("The encrypted vault database upgrade was blocked."));
  });
}

function transactionPromise<T = undefined>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("The encrypted vault database operation failed."));
  });
}
