import { deriveBitwardenArgon2idKey } from "../crypto/bitwarden-argon2";

interface ArgonRequest {
  target: "leanvault-offscreen";
  type: "crypto.argon2id";
  requestId: string;
  password: string;
  salt: string;
  iterations: number;
  memoryMiB: number;
  parallelism: number;
}

interface ArgonResponse {
  requestId: string;
  ok: boolean;
  key?: number[];
  error?: string;
}

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (!isArgonRequest(message)) {
    return false;
  }

  void derive(message)
    .then((key) => sendResponse({ requestId: message.requestId, ok: true, key } satisfies ArgonResponse))
    .catch(() =>
      sendResponse({
        requestId: message.requestId,
        ok: false,
        error: "Argon2id key derivation failed.",
      } satisfies ArgonResponse),
    );
  return true;
});

async function derive(request: ArgonRequest): Promise<number[]> {
  const key = await deriveBitwardenArgon2idKey(request.password, request.salt, {
    type: 1,
    iterations: request.iterations,
    memoryMiB: request.memoryMiB,
    parallelism: request.parallelism,
  });
  try {
    return [...key];
  } finally {
    key.fill(0);
  }
}

function isArgonRequest(value: unknown): value is ArgonRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const request = value as Record<string, unknown>;
  return (
    request.target === "leanvault-offscreen" &&
    request.type === "crypto.argon2id" &&
    typeof request.requestId === "string" &&
    typeof request.password === "string" &&
    typeof request.salt === "string" &&
    typeof request.iterations === "number" &&
    typeof request.memoryMiB === "number" &&
    typeof request.parallelism === "number"
  );
}
