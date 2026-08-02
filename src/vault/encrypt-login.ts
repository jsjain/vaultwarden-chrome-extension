import {
  decryptSymmetricBytes,
  encryptSymmetricBytes,
  encryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";

export interface LoginWriteInput {
  name: string;
  username: string;
  password: string;
  uri: string;
  notes?: string;
  favorite?: boolean;
}

export async function createEncryptedLogin(
  input: LoginWriteInput,
  userKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = validateLoginInput(input);
  const itemKey = crypto.getRandomValues(new Uint8Array(64));
  try {
    return {
      type: 1,
      folderId: null,
      organizationId: null,
      key: await encryptSymmetricBytes(itemKey, userKey),
      name: await encryptSymmetricString(clean.name, itemKey),
      notes: clean.notes ? await encryptSymmetricString(clean.notes, itemKey) : null,
      favorite: clean.favorite,
      reprompt: 0,
      fields: [],
      passwordHistory: [],
      login: await encryptedLogin(clean, itemKey),
    };
  } finally {
    itemKey.fill(0);
  }
}

export async function updateEncryptedLogin(
  rawCipher: Record<string, unknown>,
  input: LoginWriteInput,
  userKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = validateLoginInput(input);
  if (property(rawCipher, "OrganizationId", "organizationId")) {
    throw new Error("Editing organization-owned logins is not supported in this MVP.");
  }
  const encryptedKey = stringProperty(rawCipher, "Key", "key");
  const itemKey = encryptedKey ? await decryptSymmetricBytes(encryptedKey, userKey) : userKey;
  try {
    const rawLogin = recordProperty(rawCipher, "Login", "login") ?? {};
    return {
      type: numberProperty(rawCipher, "Type", "type") ?? 1,
      folderId: property(rawCipher, "FolderId", "folderId") ?? null,
      organizationId: null,
      key: encryptedKey ?? null,
      name: await encryptSymmetricString(clean.name, itemKey),
      notes: clean.notes ? await encryptSymmetricString(clean.notes, itemKey) : null,
      favorite: clean.favorite,
      reprompt: numberProperty(rawCipher, "Reprompt", "reprompt") ?? 0,
      fields: property(rawCipher, "Fields", "fields") ?? [],
      passwordHistory: property(rawCipher, "PasswordHistory", "passwordHistory") ?? [],
      attachments: property(rawCipher, "Attachments", "attachments") ?? null,
      lastKnownRevisionDate: property(rawCipher, "RevisionDate", "revisionDate") ?? null,
      login: {
        ...rawLogin,
        ...(await encryptedLogin(clean, itemKey)),
        totp: property(rawLogin, "Totp", "totp") ?? null,
        fido2Credentials: property(rawLogin, "Fido2Credentials", "fido2Credentials") ?? [],
        autofillOnPageLoad: property(rawLogin, "AutofillOnPageLoad", "autofillOnPageLoad") ?? null,
        passwordRevisionDate: property(rawLogin, "PasswordRevisionDate", "passwordRevisionDate") ?? null,
      },
    };
  } finally {
    if (encryptedKey) {
      itemKey.fill(0);
    }
  }
}

async function encryptedLogin(input: Required<LoginWriteInput>, key: Uint8Array) {
  const uris = input.uri
    ? [
        {
          uri: await encryptSymmetricString(input.uri, key),
          match: null,
          uriChecksum: await encryptSymmetricString(await sha256Base64(input.uri), key),
        },
      ]
    : [];
  return {
    username: input.username ? await encryptSymmetricString(input.username, key) : null,
    password: input.password ? await encryptSymmetricString(input.password, key) : null,
    passwordRevisionDate: null,
    totp: null,
    uris,
    autofillOnPageLoad: null,
    fido2Credentials: [],
  };
}

function validateLoginInput(input: LoginWriteInput): Required<LoginWriteInput> {
  const name = input.name.trim();
  const username = input.username.trim();
  const password = input.password;
  const notes = (input.notes ?? "").trim();
  const uri = normalizeUri(input.uri);
  if (!name || name.length > 1_000) throw new Error("Enter a login name up to 1,000 characters.");
  if (username.length > 1_000) throw new Error("Username is too long.");
  if (password.length > 10_000) throw new Error("Password is too long.");
  if (notes.length > 10_000) throw new Error("Notes are too long.");
  return { name, username, password, uri, notes, favorite: input.favorite === true };
}

function normalizeUri(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Website URLs must use HTTPS or HTTP.");
  }
  return parsed.href;
}

function property(source: Record<string, unknown>, pascal: string, camel: string): unknown {
  return source[pascal] ?? source[camel];
}
function stringProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "string" ? value : undefined;
}
function numberProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "number" ? value : undefined;
}
function recordProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
