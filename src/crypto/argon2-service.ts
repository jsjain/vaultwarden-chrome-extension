import type { Argon2idKdfConfig } from "../shared/kdf";

const OFFSCREEN_PATH = "offscreen/index.html";

interface ArgonResponse {
  requestId: string;
  ok: boolean;
  key?: number[];
  error?: string;
}

export async function deriveArgon2idMasterKey(
  password: string,
  salt: string,
  kdf: Argon2idKdfConfig,
): Promise<Uint8Array> {
  await ensureOffscreenDocument();
  const requestId = crypto.randomUUID();
  try {
    const response = (await chrome.runtime.sendMessage({
      target: "leanvault-offscreen",
      type: "crypto.argon2id",
      requestId,
      password,
      salt,
      iterations: kdf.iterations,
      memoryMiB: kdf.memoryMiB,
      parallelism: kdf.parallelism,
    })) as ArgonResponse | undefined;

    if (!response?.ok || response.requestId !== requestId || !Array.isArray(response.key)) {
      throw new Error(response?.error ?? "Argon2id key derivation returned an invalid result.");
    }
    const key = new Uint8Array(response.key);
    if (key.length !== 32) {
      throw new Error("Argon2id key derivation returned an invalid key length.");
    }
    return key;
  } finally {
    await closeOffscreenDocument();
  }
}

async function ensureOffscreenDocument(): Promise<void> {
  const documentUrl = chrome.runtime.getURL(OFFSCREEN_PATH);
  const contexts = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
    documentUrls: [documentUrl],
  });
  if (contexts.length === 0) {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      reasons: [chrome.offscreen.Reason.WORKERS],
      justification: "Derive an Argon2id master key in a transient isolated document.",
    });
  }
}

async function closeOffscreenDocument(): Promise<void> {
  try {
    await chrome.offscreen.closeDocument();
  } catch {
    // The document may already have been closed during extension shutdown.
  }
}
