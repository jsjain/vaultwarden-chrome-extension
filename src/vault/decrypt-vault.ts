import type { SyncResponse } from "../api/models";
import {
  decryptRsaKey,
  decryptSymmetricBytes,
  decryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import type { VaultItem, VaultItemDetail, VaultItemSummary, VaultUri } from "./models";

export interface VaultDecryptionResult {
  items: VaultItem[];
  failures: number;
}

export async function decryptVault(
  sync: SyncResponse,
  userKey: Uint8Array,
  identityPrivateKey?: string,
): Promise<VaultDecryptionResult> {
  if (userKey.length !== 64) {
    throw new Error("The decrypted account key has an invalid length.");
  }
  const profile = record(sync.Profile ?? sync.profile);
  const orgKeys = await decryptOrganizationKeys(profile, userKey, identityPrivateKey);
  const ciphers = sync.Ciphers ?? sync.ciphers;
  const rawCiphers = Array.isArray(ciphers) ? ciphers : [];
  const items: VaultItem[] = [];
  let failures = 0;

  for (const raw of rawCiphers) {
    try {
      const cipher = record(raw);
      if (!cipher || number(cipher, "Type", "type") !== 1 || value(cipher, "DeletedDate", "deletedDate")) {
        continue;
      }
      const organizationId = string(cipher, "OrganizationId", "organizationId");
      const baseKey = organizationId ? orgKeys.get(organizationId) : userKey;
      if (!baseKey) {
        failures += 1;
        continue;
      }
      items.push(await decryptLoginCipher(cipher, baseKey, organizationId));
    } catch {
      failures += 1;
    }
  }

  items.sort((left, right) => {
    if (left.favorite !== right.favorite) {
      return left.favorite ? -1 : 1;
    }
    return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
  });
  for (const organizationKey of orgKeys.values()) {
    organizationKey.fill(0);
  }
  return { items, failures };
}

export function listVaultItems(
  items: VaultItem[],
  queryInput: string,
  currentUrl?: string,
): VaultItemSummary[] {
  const query = queryInput.trim().toLocaleLowerCase();
  return items
    .map((item) => ({ item, matched: currentUrl ? matchesCurrentUrl(item, currentUrl) : false }))
    .filter(({ item, matched }) => {
      if (!query) {
        return true;
      }
      return (
        matched ||
        item.name.toLocaleLowerCase().includes(query) ||
        item.username.toLocaleLowerCase().includes(query) ||
        item.uris.some((uri) => uri.uri.toLocaleLowerCase().includes(query))
      );
    })
    .sort((left, right) => Number(right.matched) - Number(left.matched))
    .map(({ item, matched }) => ({
      id: item.id,
      name: item.name,
      username: item.username,
      favorite: item.favorite,
      requiresReprompt: item.reprompt,
      editable: item.organizationId === undefined,
      matched,
      ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
    }));
}

export function getVaultItemDetail(
  item: VaultItem,
  currentUrl?: string,
  repromptSatisfied = false,
): VaultItemDetail {
  const protectedItem = item.reprompt && !repromptSatisfied;
  return {
    id: item.id,
    name: item.name,
    username: item.username,
    password: protectedItem ? "" : item.password,
    hasTotp: !protectedItem && Boolean(item.totp),
    protected: protectedItem,
    favorite: item.favorite,
    requiresReprompt: item.reprompt,
    matched: currentUrl ? matchesCurrentUrl(item, currentUrl) : false,
    uris: item.uris,
    editable: item.organizationId === undefined,
    ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
    ...(protectedItem || item.notes === undefined ? {} : { notes: item.notes }),
  };
}

export function matchesCurrentUrl(item: VaultItem, currentUrl: string): boolean {
  const page = safeUrl(currentUrl);
  if (!page || (page.protocol !== "http:" && page.protocol !== "https:")) {
    return false;
  }
  return item.uris.some(({ uri, match }) => {
    // Bitwarden URI match strategies: Domain (0/default), Host (1),
    // Starts With (2), Exact (3), Regular Expression (4), and Never (5).
    // Unknown strategies fail closed so a future server value cannot broaden access.
    if (match === 5) {
      return false;
    }
    if (match === 4) {
      try {
        return new RegExp(uri, "i").test(page.href);
      } catch {
        return false;
      }
    }
    const saved = safeUrl(uri);
    if (!saved) {
      return false;
    }
    if (match === 3) {
      return page.href === saved.href;
    }
    if (match === 2) {
      return page.href.startsWith(saved.href);
    }
    if (match === 1) {
      return page.hostname === saved.hostname && page.port === saved.port;
    }
    if (match !== undefined && match !== 0) {
      return false;
    }
    const pageHost = page.hostname.toLocaleLowerCase();
    const savedHost = saved.hostname.toLocaleLowerCase();
    return pageHost === savedHost || pageHost.endsWith(`.${savedHost}`);
  });
}

async function decryptLoginCipher(
  cipher: Record<string, unknown>,
  baseKey: Uint8Array,
  organizationId?: string,
): Promise<VaultItem> {
  const encryptedItemKey = string(cipher, "Key", "key");
  const itemKey = encryptedItemKey
    ? await decryptSymmetricBytes(encryptedItemKey, baseKey)
    : baseKey;
  try {
    if (itemKey.length !== 64) {
      throw new Error("A cipher key has an invalid length.");
    }
    const login = record(value(cipher, "Login", "login"));
    if (!login) {
      throw new Error("Login cipher is missing its login payload.");
    }
    const id = requiredString(cipher, "Id", "id");
    const name = await decryptRequiredString(cipher, itemKey, "Name", "name");
    const username = await decryptOptionalString(login, itemKey, "Username", "username");
    const canViewPassword = value(cipher, "ViewPassword", "viewPassword") !== false;
    const password = canViewPassword
      ? await decryptOptionalString(login, itemKey, "Password", "password")
      : undefined;
    const totp = canViewPassword
      ? await decryptOptionalString(login, itemKey, "Totp", "totp")
      : undefined;
    const notes = await decryptOptionalString(cipher, itemKey, "Notes", "notes");
    const uris = await decryptUris(login, itemKey, Boolean(encryptedItemKey));

    return {
      id,
      name,
      username: username ?? "",
      password: password ?? "",
      favorite: boolean(cipher, "Favorite", "favorite"),
      reprompt: number(cipher, "Reprompt", "reprompt") === 1,
      uris,
      ...(organizationId === undefined ? {} : { organizationId }),
      ...(totp === undefined ? {} : { totp }),
      ...(notes === undefined ? {} : { notes }),
    };
  } finally {
    if (encryptedItemKey) {
      itemKey.fill(0);
    }
  }
}

async function decryptUris(
  login: Record<string, unknown>,
  key: Uint8Array,
  requiresChecksum: boolean,
): Promise<VaultUri[]> {
  const rawUris = value(login, "Uris", "uris");
  if (!Array.isArray(rawUris)) {
    return [];
  }
  const uris: VaultUri[] = [];
  for (const raw of rawUris) {
    try {
      const entry = record(raw);
      if (!entry) {
        continue;
      }
      const encryptedUri = string(entry, "Uri", "uri");
      if (!encryptedUri) {
        continue;
      }
      const uri = await decryptSymmetricString(encryptedUri, key);
      if (requiresChecksum) {
        const encryptedChecksum = string(entry, "UriChecksum", "uriChecksum");
        if (!encryptedChecksum) {
          continue;
        }
        const expected = await decryptSymmetricString(encryptedChecksum, key);
        const actual = await sha256Base64(uri);
        if (expected !== actual) {
          continue;
        }
      }
      const match = number(entry, "Match", "match");
      uris.push({ uri, ...(match === undefined ? {} : { match }) });
    } catch {
      // A damaged URI does not make the rest of a login unusable.
    }
  }
  return uris;
}

async function decryptOrganizationKeys(
  profile: Record<string, unknown> | undefined,
  userKey: Uint8Array,
  identityPrivateKey?: string,
): Promise<Map<string, Uint8Array>> {
  const result = new Map<string, Uint8Array>();
  if (!profile) {
    return result;
  }
  const encryptedPrivateKey = string(profile, "PrivateKey", "privateKey") ?? identityPrivateKey;
  if (!encryptedPrivateKey) {
    return result;
  }
  let privateKey: Uint8Array;
  try {
    privateKey = await decryptSymmetricBytes(encryptedPrivateKey, userKey);
  } catch {
    return result;
  }
  const organizationsNew = value(profile, "OrganizationsNew", "organizationsNew");
  const organizationsLegacy = value(profile, "Organizations", "organizations");
  const organizationsValue = Array.isArray(organizationsNew) && organizationsNew.length > 0
    ? organizationsNew
    : organizationsLegacy;
  if (!Array.isArray(organizationsValue)) {
    privateKey.fill(0);
    return result;
  }
  for (const raw of organizationsValue) {
    try {
      const organization = record(raw);
      if (!organization) {
        continue;
      }
      const id = requiredString(organization, "Id", "id");
      const encryptedKey = requiredString(organization, "Key", "key");
      const key = await decryptRsaKey(encryptedKey, privateKey);
      if (key.length === 64) {
        result.set(id, key);
      }
    } catch {
      // Unsupported organization keys are isolated to that organization.
    }
  }
  privateKey.fill(0);
  return result;
}

async function decryptRequiredString(
  source: Record<string, unknown>,
  key: Uint8Array,
  pascal: string,
  camel: string,
): Promise<string> {
  const encrypted = requiredString(source, pascal, camel);
  return decryptSymmetricString(encrypted, key);
}

async function decryptOptionalString(
  source: Record<string, unknown>,
  key: Uint8Array,
  pascal: string,
  camel: string,
): Promise<string | undefined> {
  const encrypted = string(source, pascal, camel);
  return encrypted ? decryptSymmetricString(encrypted, key) : undefined;
}

function safeUrl(input: string): URL | null {
  const trimmed = input.trim();
  if (!trimmed) {
    return null;
  }
  try {
    return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
}

function record(input: unknown): Record<string, unknown> | undefined {
  return typeof input === "object" && input !== null && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : undefined;
}

function value(source: Record<string, unknown>, pascal: string, camel: string): unknown {
  return source[pascal] ?? source[camel];
}

function string(source: Record<string, unknown>, pascal: string, camel: string): string | undefined {
  const result = value(source, pascal, camel);
  return typeof result === "string" ? result : undefined;
}

function requiredString(source: Record<string, unknown>, pascal: string, camel: string): string {
  const result = string(source, pascal, camel);
  if (!result) {
    throw new Error(`Vault data is missing ${pascal}.`);
  }
  return result;
}

function number(source: Record<string, unknown>, pascal: string, camel: string): number | undefined {
  const result = value(source, pascal, camel);
  return typeof result === "number" ? result : undefined;
}

function boolean(source: Record<string, unknown>, pascal: string, camel: string): boolean {
  return value(source, pascal, camel) === true;
}
