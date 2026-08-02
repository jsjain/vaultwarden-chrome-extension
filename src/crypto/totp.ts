const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

export interface TotpResult {
  code: string;
  period: number;
  remaining: number;
}

interface TotpConfig {
  secret: Uint8Array;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  digits: number;
  period: number;
  steam: boolean;
}

export async function generateTotp(seed: string, now = Date.now()): Promise<TotpResult> {
  const config = parseSeed(seed);
  const counter = Math.floor(now / 1000 / config.period);
  const message = new Uint8Array(8);
  let remainingCounter = counter;
  for (let index = 7; index >= 0; index -= 1) {
    message[index] = remainingCounter & 0xff;
    remainingCounter = Math.floor(remainingCounter / 256);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(config.secret),
    { name: "HMAC", hash: config.algorithm },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  const code = config.steam
    ? steamCode(binary)
    : String(binary % 10 ** config.digits).padStart(config.digits, "0");
  const elapsed = Math.floor(now / 1000) % config.period;
  return { code, period: config.period, remaining: config.period - elapsed };
}

function parseSeed(input: string): TotpConfig {
  const trimmed = input.trim();
  let secret = trimmed;
  let algorithm: TotpConfig["algorithm"] = "SHA-1";
  let digits = 6;
  let period = 30;
  let steam = false;

  if (/^otpauth:\/\//i.test(trimmed)) {
    const uri = new URL(trimmed);
    if (uri.protocol !== "otpauth:" || uri.hostname.toLowerCase() !== "totp") {
      throw new Error("Only TOTP authenticator seeds are supported.");
    }
    secret = uri.searchParams.get("secret") ?? "";
    const algorithmInput = (uri.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
    if (algorithmInput === "SHA1") algorithm = "SHA-1";
    else if (algorithmInput === "SHA256") algorithm = "SHA-256";
    else if (algorithmInput === "SHA512") algorithm = "SHA-512";
    else throw new Error("The TOTP seed uses an unsupported hash algorithm.");
    digits = positiveInteger(uri.searchParams.get("digits"), 6, 6, 10, "TOTP digit count");
    period = positiveInteger(uri.searchParams.get("period"), 30, 5, 300, "TOTP period");
    steam = uri.searchParams.get("issuer")?.toLowerCase() === "steam";
  }
  const decoded = decodeBase32(secret);
  if (decoded.length < 10 || decoded.length > 128) {
    throw new Error("The TOTP seed has an invalid length.");
  }
  return { secret: decoded, algorithm, digits, period, steam };
}

function decodeBase32(value: string): Uint8Array {
  const normalized = value.toUpperCase().replace(/[\s=-]/g, "");
  if (!normalized || /[^A-Z2-7]/.test(normalized)) {
    throw new Error("The TOTP seed is not valid Base32.");
  }
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of normalized) {
    const code = character.charCodeAt(0);
    const next = code >= 65 && code <= 90 ? code - 65 : code - 24;
    buffer = (buffer << 5) | next;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(output);
}

function steamCode(input: number): string {
  let value = input;
  let output = "";
  for (let index = 0; index < 5; index += 1) {
    output += STEAM_ALPHABET[value % STEAM_ALPHABET.length];
    value = Math.floor(value / STEAM_ALPHABET.length);
  }
  return output;
}

function positiveInteger(
  value: string | null,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (value === null || value === "") {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || String(parsed) !== value || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} is invalid.`);
  }
  return parsed;
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}
