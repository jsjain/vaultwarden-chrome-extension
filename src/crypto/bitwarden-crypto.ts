import { KdfType, type KdfConfig } from "../shared/kdf";
import { concatenate, decodeUtf8, equalConstantTime, fromBase64, toBase64, utf8 } from "./bytes";

export interface ParsedEncString {
  type: number;
  parts: Uint8Array[];
}

export async function derivePbkdf2MasterKey(
  password: string,
  salt: string,
  iterations: number,
): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", arrayBuffer(utf8(password)), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: arrayBuffer(utf8(salt)), iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  masterPassword: string,
): Promise<string> {
  const material = await crypto.subtle.importKey("raw", arrayBuffer(masterKey), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: arrayBuffer(utf8(masterPassword)), iterations: 1 },
    material,
    256,
  );
  return toBase64(new Uint8Array(bits));
}

export async function stretchMasterKey(masterKey: Uint8Array): Promise<Uint8Array> {
  if (masterKey.length !== 32) {
    throw new Error("A Bitwarden master key must contain exactly 32 bytes.");
  }
  const [encryptionKey, authenticationKey] = await Promise.all([
    hkdfExpand(masterKey, utf8("enc"), 32),
    hkdfExpand(masterKey, utf8("mac"), 32),
  ]);
  return concatenate(encryptionKey, authenticationKey);
}

export function parseEncString(value: string): ParsedEncString {
  if (!value) {
    throw new Error("Encrypted value is empty.");
  }
  const dot = value.indexOf(".");
  const type = dot === -1 ? 0 : Number.parseInt(value.slice(0, dot), 10);
  const payload = dot === -1 ? value : value.slice(dot + 1);
  if (!Number.isInteger(type)) {
    throw new Error("Encrypted value has an invalid type.");
  }
  const encodedParts = payload.split("|");
  const expectedParts: Record<number, number> = { 0: 2, 2: 3, 3: 1, 4: 1, 5: 2, 6: 2, 7: 1 };
  if (expectedParts[type] !== encodedParts.length) {
    throw new Error(`Encrypted value type ${type} has an invalid shape.`);
  }
  return { type, parts: encodedParts.map(fromBase64) };
}

export async function decryptSymmetricBytes(value: string, key: Uint8Array): Promise<Uint8Array> {
  const encrypted = parseEncString(value);
  if (encrypted.type === 7) {
    throw new Error("This vault uses Bitwarden encryption v2, which this build does not support yet.");
  }
  if (encrypted.type !== 0 && encrypted.type !== 2) {
    throw new Error(`Encrypted value type ${encrypted.type} is not symmetric AES-CBC data.`);
  }
  if (key.length !== 32 && key.length !== 64) {
    throw new Error("Symmetric keys must contain 32 or 64 bytes.");
  }
  const encryptionKey = key.subarray(0, 32);
  const iv = encrypted.parts[0]!;
  const ciphertext = encrypted.parts[1]!;
  if (iv.length !== 16 || ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error("Encrypted AES-CBC data has an invalid length.");
  }

  if (encrypted.type === 2) {
    if (key.length !== 64) {
      throw new Error("Authenticated encrypted data requires a 64-byte key.");
    }
    const remoteMac = encrypted.parts[2]!;
    const localMac = await hmacSha256(key.subarray(32, 64), concatenate(iv, ciphertext));
    if (!equalConstantTime(localMac, remoteMac)) {
      throw new Error("Encrypted data failed its integrity check.");
    }
  }

  const imported = await crypto.subtle.importKey("raw", arrayBuffer(encryptionKey), "AES-CBC", false, [
    "decrypt",
  ]);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: arrayBuffer(iv) },
        imported,
        arrayBuffer(ciphertext),
      ),
    );
  } catch {
    throw new Error("Encrypted data could not be decrypted.");
  }
}

export async function decryptSymmetricString(value: string, key: Uint8Array): Promise<string> {
  return decodeUtf8(await decryptSymmetricBytes(value, key));
}

export async function encryptSymmetricBytes(value: Uint8Array, key: Uint8Array): Promise<string> {
  if (key.length !== 64) {
    throw new Error("Authenticated encryption requires a 64-byte key.");
  }
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const imported = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(key.subarray(0, 32)),
    "AES-CBC",
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv: arrayBuffer(iv) }, imported, arrayBuffer(value)),
  );
  const mac = await hmacSha256(key.subarray(32, 64), concatenate(iv, ciphertext));
  return `2.${toBase64(iv)}|${toBase64(ciphertext)}|${toBase64(mac)}`;
}

export function encryptSymmetricString(value: string, key: Uint8Array): Promise<string> {
  return encryptSymmetricBytes(utf8(value), key);
}

export async function decryptRsaKey(value: string, privateKey: Uint8Array): Promise<Uint8Array> {
  const encrypted = parseEncString(value);
  if (encrypted.type !== 3 && encrypted.type !== 4) {
    throw new Error(`Organization key type ${encrypted.type} is not supported.`);
  }
  const hash = encrypted.type === 3 ? "SHA-256" : "SHA-1";
  const key = await crypto.subtle.importKey(
    "pkcs8",
    arrayBuffer(privateKey),
    { name: "RSA-OAEP", hash },
    false,
    ["decrypt"],
  );
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, arrayBuffer(encrypted.parts[0]!)),
    );
  } catch {
    throw new Error("An organization key could not be decrypted.");
  }
}

export async function sha256Base64(value: string): Promise<string> {
  return toBase64(
    new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBuffer(utf8(value)))),
  );
}

export function kdfFingerprint(kdf: KdfConfig): string {
  return kdf.type === KdfType.Pbkdf2Sha256
    ? `pbkdf2:${kdf.iterations}`
    : `argon2id:${kdf.iterations}:${kdf.memoryMiB}:${kdf.parallelism}`;
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  if (length <= 0 || length > 32) {
    throw new Error("This HKDF expansion supports output lengths from 1 to 32 bytes.");
  }
  const block = await hmacSha256(prk, concatenate(info, new Uint8Array([1])));
  return block.subarray(0, length);
}

async function hmacSha256(key: Uint8Array, value: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, arrayBuffer(value)));
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}
