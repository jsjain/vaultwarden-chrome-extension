import { VaultwardenClient } from "../api/vaultwarden-client";
import { ApiError } from "../api/api-error";
import { deriveArgon2idMasterKey } from "../crypto/argon2-service";
import {
  decryptSymmetricBytes,
  deriveMasterPasswordHash,
  derivePbkdf2MasterKey,
  kdfFingerprint,
  stretchMasterKey,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import { equalConstantTime, wipe } from "../crypto/bytes";
import { generateTotp, type TotpResult } from "../crypto/totp";
import { KdfType, type KdfConfig } from "../shared/kdf";
import type {
  AuthLoginRequest,
  PublicAppState,
  VaultListRequest,
} from "../shared/messages";
import { clearEncryptedSync, readEncryptedSync, writeEncryptedSync } from "../shared/database";
import {
  clearAccountMetadata,
  clearAuthSession,
  getOrCreateDeviceIdentifier,
  readAccountMetadata,
  readAuthSession,
  readServerSnapshot,
  updateSessionUserKey,
  writeAccountMetadata,
  writeAuthSession,
  type AccountMetadata,
  type AuthSession,
} from "../shared/storage";
import { decryptVault, getVaultItemDetail, listVaultItems, matchesCurrentUrl } from "../vault/decrypt-vault";
import type { VaultItem, VaultItemDetail, VaultItemSummary } from "../vault/models";
import {
  createEncryptedLogin,
  updateEncryptedLogin,
  type LoginWriteInput,
} from "../vault/encrypt-login";
import { fillActiveTab } from "./fill";
import type { BrowserIntegrationOptions } from "../shared/settings";

export class VaultController {
  private readonly client = new VaultwardenClient();
  private vaultCache: VaultItem[] | null = null;
  private decryptionFailures = 0;
  private readonly repromptAuthorizations = new Map<string, number>();
  private readonly pendingCaptures = new Map<number, PendingCapture>();
  private readonly pendingReady = chrome.storage.session.get("pendingSiteLogins").then((stored) => {
    for (const [tabId, pending] of (stored.pendingSiteLogins ?? []) as [number, PendingCapture][]) {
      if (pending.rememberUntil > Date.now()) this.pendingCaptures.set(tabId, pending);
    }
  });
  private sessionRevision = 0;
  private refreshTask: Promise<AuthSession> | null = null;
  private syncTask: Promise<{ itemCount: number; failures: number }> | null = null;

  async getState(): Promise<PublicAppState> {
    const [snapshot, account, session] = await Promise.all([
      readServerSnapshot(),
      readAccountMetadata(),
      readAuthSession(),
    ]);
    if (!snapshot) {
      return { phase: "setup" };
    }
    if (!account || !session) {
      return { phase: "signed-out", snapshot, ...(account ? { email: account.email } : {}) };
    }
    if (!session.userKey) {
      return {
        phase: "locked",
        snapshot,
        email: account.email,
        itemCount: account.itemCount ?? 0,
        ...(account.lastSync ? { lastSync: account.lastSync } : {}),
      };
    }
    return {
      phase: "unlocked",
      snapshot,
      email: account.email,
      itemCount: account.itemCount ?? 0,
      decryptionFailures: this.decryptionFailures,
      ...(account.lastSync ? { lastSync: account.lastSync } : {}),
    };
  }

  async login(request: AuthLoginRequest): Promise<
    | { status: "unlocked"; itemCount: number; failures: number }
    | { status: "two-factor"; providers: number[]; providerDetails: Record<string, Record<string, string>> }
    | { status: "device-verification"; message: string }
  > {
    const email = normalizeEmail(request.email);
    if (!request.masterPassword) {
      throw new Error("Enter your master password.");
    }
    const prelogin = await this.client.getPrelogin(request.baseUrl, email);
    const masterKey = await deriveMasterKey(request.masterPassword, email, prelogin.kdf);
    try {
      const masterPasswordHash = await deriveMasterPasswordHash(masterKey, request.masterPassword);
      const login = await this.client.loginWithPassword({
        baseUrl: request.baseUrl,
        email,
        masterPasswordHash,
        deviceIdentifier: await getOrCreateDeviceIdentifier(),
        ...(request.twoFactorProvider === undefined
          ? {}
          : { twoFactorProvider: request.twoFactorProvider }),
        ...(request.twoFactorToken ? { twoFactorToken: request.twoFactorToken } : {}),
        ...(request.twoFactorRemember === undefined
          ? {}
          : { twoFactorRemember: request.twoFactorRemember }),
        ...(request.newDeviceOtp ? { newDeviceOtp: request.newDeviceOtp } : {}),
      });
      if (login.kind === "two-factor") {
        return {
          status: "two-factor",
          providers: login.providers,
          providerDetails: login.providerDetails,
        };
      }
      if (login.kind === "device-verification") {
        return { status: "device-verification", message: login.message };
      }
      if (kdfFingerprint(login.kdf) !== kdfFingerprint(prelogin.kdf)) {
        throw new Error("The server changed KDF parameters during login; refusing to continue.");
      }
      const stretchedMasterKey = await stretchMasterKey(masterKey);
      let userKey: Uint8Array;
      try {
        userKey = await decryptSymmetricBytes(login.wrappedUserKey, stretchedMasterKey);
      } finally {
        wipe(stretchedMasterKey);
      }
      if (userKey.length !== 64) {
        wipe(userKey);
        throw new Error("The server returned an invalid encrypted account key.");
      }
      const expiresAt = login.expiresIn ? Date.now() + login.expiresIn * 1000 : undefined;
      await writeAuthSession({
        baseUrl: request.baseUrl,
        email,
        accessToken: login.accessToken,
        userKey: [...userKey],
        ...(login.refreshToken ? { refreshToken: login.refreshToken } : {}),
        ...(expiresAt === undefined ? {} : { accessTokenExpiresAt: expiresAt }),
      });
      await writeAccountMetadata({
        baseUrl: request.baseUrl,
        email,
        kdf: login.kdf,
        wrappedUserKey: login.wrappedUserKey,
        ...(login.privateKey ? { privateKey: login.privateKey } : {}),
      });
      try {
        const result = await this.sync();
        return { status: "unlocked", itemCount: result.itemCount, failures: result.failures };
      } catch (error) {
        this.clearCache();
        await Promise.all([clearAuthSession(), clearAccountMetadata(), clearEncryptedSync(), this.clearPendingSiteLogins()]);
        throw error;
      } finally {
        wipe(userKey);
      }
    } finally {
      wipe(masterKey);
    }
  }

  async unlock(masterPassword: string): Promise<{ itemCount: number; failures: number }> {
    const [account, session] = await Promise.all([readAccountMetadata(), readAuthSession()]);
    if (!account || !session) {
      throw new Error("The account session has expired. Sign in again.");
    }
    const masterKey = await deriveMasterKey(masterPassword, account.email, account.kdf);
    const stretched = await stretchMasterKey(masterKey);
    wipe(masterKey);
    let userKey: Uint8Array;
    try {
      userKey = await decryptSymmetricBytes(account.wrappedUserKey, stretched);
    } finally {
      wipe(stretched);
    }
    if (userKey.length !== 64) {
      wipe(userKey);
      throw new Error("The master password could not unlock this account.");
    }
    try {
      await updateSessionUserKey(userKey);
      const items = await this.loadVault(userKey, account);
      return { itemCount: items.length, failures: this.decryptionFailures };
    } catch (error) {
      await updateSessionUserKey(null);
      throw error;
    } finally {
      wipe(userKey);
    }
  }

  async sendTwoFactorEmail(baseUrl: string, emailInput: string, masterPassword: string): Promise<void> {
    const email = normalizeEmail(emailInput);
    if (!masterPassword) {
      throw new Error("Enter your master password before requesting an email code.");
    }
    const prelogin = await this.client.getPrelogin(baseUrl, email);
    const masterKey = await deriveMasterKey(masterPassword, email, prelogin.kdf);
    try {
      const hash = await deriveMasterPasswordHash(masterKey, masterPassword);
      await this.client.sendTwoFactorEmail(
        baseUrl,
        email,
        hash,
        await getOrCreateDeviceIdentifier(),
      );
    } finally {
      wipe(masterKey);
    }
  }

  async lock(): Promise<void> {
    this.clearCache();
    try {
      await updateSessionUserKey(null);
    } finally {
      // Invalidate work that started while the stored key was being removed.
      this.clearCache();
    }
    await this.clearPendingSiteLogins();
  }

  async logout(): Promise<void> {
    this.clearCache();
    try {
      await Promise.all([clearAuthSession(), clearAccountMetadata(), clearEncryptedSync()]);
    } finally {
      this.clearCache();
    }
    await this.clearPendingSiteLogins();
  }

  async sync(): Promise<{ itemCount: number; failures: number }> {
    const revision = this.sessionRevision;
    const task = (this.syncTask ?? Promise.resolve()).catch(() => undefined).then(() => {
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      return this.performSync();
    });
    this.syncTask = task;
    try {
      return await task;
    } finally {
      if (this.syncTask === task) this.syncTask = null;
    }
  }

  private async performSync(): Promise<{ itemCount: number; failures: number }> {
    const revision = this.sessionRevision;
    let session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = session.userKey ? requireUserKey(session.userKey) : null;
    try {
      let payload;
      try {
        payload = await this.client.getSync(session.baseUrl, session.accessToken);
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401 || !session.refreshToken) {
          throw error;
        }
        session = await this.refreshSession(session);
        payload = await this.client.getSync(session.baseUrl, session.accessToken);
      }
      const account = await requireAccount();
      const decrypted = userKey ? await decryptVault(payload, userKey, account.privateKey) : null;
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      await writeEncryptedSync(payload);
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      this.vaultCache = decrypted?.items ?? null;
      this.decryptionFailures = decrypted?.failures ?? 0;
      const updated: AccountMetadata = {
        ...account,
        lastSync: new Date().toISOString(),
        itemCount: decrypted?.items.length ?? account.itemCount ?? 0,
      };
      await writeAccountMetadata(updated);
      return { itemCount: updated.itemCount!, failures: this.decryptionFailures };
    } finally {
      if (userKey) wipe(userKey);
    }
  }

  async list(request: VaultListRequest): Promise<VaultItemSummary[]> {
    const items = await this.requireVault();
    return listVaultItems(items, request.query, request.currentUrl);
  }

  async detail(id: string, currentUrl?: string): Promise<VaultItemDetail> {
    const item = await this.findItem(id);
    return getVaultItemDetail(item, currentUrl, this.isRepromptAuthorized(item));
  }

  async fill(id: string): Promise<{ username: boolean; password: boolean }> {
    const item = await this.findItem(id);
    if (item.reprompt && !this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected login before filling it.");
    }
    return fillActiveTab(item);
  }

  async totp(id: string): Promise<TotpResult> {
    const item = await this.findItem(id);
    if (!item.totp) {
      throw new Error("This login does not have an authenticator key.");
    }
    if (item.reprompt && !this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected login first.");
    }
    return generateTotp(item.totp);
  }

  async createLogin(input: LoginWriteInput): Promise<void> {
    const session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = requireUserKey(session.userKey);
    try {
      const payload = await createEncryptedLogin(input, userKey);
      await this.client.createCipher(session.baseUrl, session.accessToken, payload);
      // The write is committed; refresh failures are retried by the minute alarm.
      await this.sync().catch(() => undefined);
    } finally {
      wipe(userKey);
    }
  }

  async updateLogin(id: string, input: LoginWriteInput): Promise<void> {
    const item = await this.findItem(id);
    if (item.organizationId) {
      throw new Error("Editing organization-owned logins is not supported in this MVP.");
    }
    if (item.reprompt && !this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected login before editing it.");
    }
    const session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = requireUserKey(session.userKey);
    try {
      const raw = await this.client.getCipher(session.baseUrl, session.accessToken, id);
      const payload = await updateEncryptedLogin(raw, input, userKey);
      await this.client.updateCipher(session.baseUrl, session.accessToken, id, payload);
      // The write is committed; refresh failures must not invite a second write.
      await this.sync().catch(() => undefined);
    } finally {
      wipe(userKey);
    }
  }

  async siteSuggestions(url: string): Promise<VaultItemSummary[]> {
    const insecure = new URL(url).protocol === "http:";
    return listVaultItems(await this.requireVault(), "", url)
      .filter((item) => item.matched && !(insecure && item.uri?.startsWith("https://")))
      .slice(0, 10);
  }

  async siteCredential(id: string, url: string): Promise<{ username: string; password: string }> {
    const item = await this.findItem(id);
    if (!matchesCurrentUrl(item, url)) throw new Error("This login is not mapped to the current website.");
    if (new URL(url).protocol === "http:" && item.uris.some(({ uri }) => /^https:\/\//i.test(uri))) {
      throw new Error("Refusing to fill an HTTPS login into an insecure HTTP page.");
    }
    if (item.reprompt && !this.isRepromptAuthorized(item)) {
      throw new Error("Open LeanVault and confirm the master password for this protected login.");
    }
    return { username: item.username, password: item.password };
  }

  async inspectSiteLogin(
    tabId: number,
    url: string,
    username: string,
    password: string,
    options: BrowserIntegrationOptions,
    frameId = 0,
  ): Promise<({ id: string; expiresAt: number; action: "save" | "update" } & LoginWriteInput) | null> {
    await this.pendingReady;
    const fingerprint = await sha256Base64(JSON.stringify([new URL(url).origin, username, password]));
    const matches = (await this.requireVault()).filter((item) => matchesCurrentUrl(item, url));
    const previous = this.pendingCaptures.get(tabId);
    if (previous?.fingerprint === fingerprint && previous.rememberUntil > Date.now()) {
      return this.pendingSitePrompt(tabId, url, frameId);
    }
    if (matches.some((item) => item.username === username && item.password === password)) return null;
    const update = matches.find(
      (item) => item.username === username && !item.organizationId && !item.reprompt,
    );
    if (update && !options.askUpdateLogin) return null;
    if (!update && !options.askAddLogin) return null;
    const name = update?.name ?? new URL(url).hostname.replace(/^www\./, "");
    const prompt = {
      id: crypto.randomUUID(),
      expiresAt: Date.now() + options.savePromptTimeoutSeconds * 1000,
      action: update ? "update" as const : "save" as const,
      name,
      username,
      password,
      uri: url,
    };
    this.pendingCaptures.set(tabId, {
      ...prompt,
      url,
      username,
      password,
      ...(update ? { updateId: update.id } : {}),
      frameId,
      fingerprint,
      // ponytail: deduplicate a login flow for five minutes; use navigation tracking if flows need longer.
      rememberUntil: Date.now() + 300_000,
    });
    await this.persistPendingCaptures();
    return prompt;
  }

  async pendingSitePrompt(tabId: number, url: string, frameId = 0) {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (!pending || pending.frameId !== frameId || new URL(pending.url).origin !== new URL(url).origin) return null;
    if (pending.dismissed || pending.expiresAt <= Date.now()) {
      await this.dismissPendingSiteLogin(tabId, pending.id);
      return null;
    }
    return {
      id: pending.id,
      expiresAt: pending.expiresAt,
      action: pending.action,
      name: pending.name,
      username: pending.username,
      password: pending.password,
      uri: pending.url,
    };
  }

  async savePendingSiteLogin(tabId: number, promptId: string, edited?: LoginWriteInput): Promise<void> {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (!pending || pending.dismissed || pending.id !== promptId || pending.expiresAt <= Date.now()) {
      throw new Error("The save prompt expired. Submit the login form again.");
    }
    if (pending.saving) throw new Error("This login is already being saved.");
    pending.saving = true;
    const input: LoginWriteInput = edited ?? {
      name: pending.name,
      username: pending.username,
      password: pending.password,
      uri: pending.url,
    };
    try {
      if (pending.updateId) await this.updateLogin(pending.updateId, input);
      else await this.createLogin(input);
      await this.dismissPendingSiteLogin(tabId, promptId);
    } finally {
      pending.saving = false;
    }
  }

  async dismissPendingSiteLogin(tabId: number, promptId: string): Promise<void> {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (pending?.id !== promptId) return;
    pending.dismissed = true;
    pending.username = "";
    pending.password = "";
    await this.persistPendingCaptures();
  }

  async clearPendingSiteLogins(tabId?: number): Promise<void> {
    await this.pendingReady;
    if (tabId === undefined) this.pendingCaptures.clear();
    else this.pendingCaptures.delete(tabId);
    await this.persistPendingCaptures();
  }

  private async persistPendingCaptures(): Promise<void> {
    for (const [tabId, pending] of this.pendingCaptures) {
      if (pending.rememberUntil <= Date.now()) this.pendingCaptures.delete(tabId);
      else if (pending.expiresAt <= Date.now() && !pending.saving) {
        pending.dismissed = true;
        pending.username = "";
        pending.password = "";
      }
    }
    await chrome.storage.session.set({ pendingSiteLogins: [...this.pendingCaptures] });
  }

  async authorizeReprompt(id: string, masterPassword: string): Promise<void> {
    const item = await this.findItem(id);
    if (!item.reprompt) {
      return;
    }
    const [account, session] = await Promise.all([requireAccount(), requireSession()]);
    const sessionKey = requireUserKey(session.userKey);
    try {
      const masterKey = await deriveMasterKey(masterPassword, account.email, account.kdf);
      const stretched = await stretchMasterKey(masterKey);
      wipe(masterKey);
      let candidate: Uint8Array;
      try {
        candidate = await decryptSymmetricBytes(account.wrappedUserKey, stretched);
      } finally {
        wipe(stretched);
      }
      const valid = equalConstantTime(candidate, sessionKey);
      wipe(candidate);
      if (!valid) {
        throw new Error("The master password is incorrect.");
      }
      this.repromptAuthorizations.set(id, Date.now() + 60_000);
    } finally {
      wipe(sessionKey);
    }
  }

  private async findItem(id: string): Promise<VaultItem> {
    const item = (await this.requireVault()).find((candidate) => candidate.id === id);
    if (!item) {
      throw new Error("The selected vault item no longer exists.");
    }
    return item;
  }

  private async requireVault(): Promise<VaultItem[]> {
    if (this.vaultCache) {
      return this.vaultCache;
    }
    const [account, session] = await Promise.all([requireAccount(), requireSession()]);
    const userKey = requireUserKey(session.userKey);
    try {
      return await this.loadVault(userKey, account);
    } finally {
      wipe(userKey);
    }
  }

  private async loadVault(userKey: Uint8Array, account: AccountMetadata): Promise<VaultItem[]> {
    const payload = await readEncryptedSync();
    if (!payload) {
      const result = await this.sync();
      if (!this.vaultCache) {
        throw new Error(`Vault sync completed with ${result.itemCount} items but no cache.`);
      }
      return this.vaultCache;
    }
    const decrypted = await decryptVault(payload, userKey, account.privateKey);
    this.vaultCache = decrypted.items;
    this.decryptionFailures = decrypted.failures;
    if (account.itemCount !== decrypted.items.length) {
      await writeAccountMetadata({ ...account, itemCount: decrypted.items.length });
    }
    return decrypted.items;
  }

  private clearCache(): void {
    this.sessionRevision += 1;
    if (this.vaultCache) {
      for (const item of this.vaultCache) {
        item.username = "";
        item.password = "";
        delete item.totp;
        delete item.notes;
      }
    }
    this.vaultCache = null;
    this.decryptionFailures = 0;
    this.repromptAuthorizations.clear();
  }

  private isRepromptAuthorized(item: VaultItem): boolean {
    if (!item.reprompt) {
      return true;
    }
    const expiresAt = this.repromptAuthorizations.get(item.id) ?? 0;
    if (expiresAt <= Date.now()) {
      this.repromptAuthorizations.delete(item.id);
      return false;
    }
    return true;
  }

  private async refreshSessionIfNeeded(session: Awaited<ReturnType<typeof requireSession>>) {
    if (
      session.accessTokenExpiresAt !== undefined &&
      session.accessTokenExpiresAt <= Date.now() + 60_000 &&
      session.refreshToken
    ) {
      return this.refreshSession(session);
    }
    return session;
  }

  private async refreshSession(session: AuthSession): Promise<AuthSession> {
    if (this.refreshTask) return this.refreshTask;
    const task = this.performSessionRefresh(session);
    this.refreshTask = task;
    try {
      return await task;
    } finally {
      if (this.refreshTask === task) this.refreshTask = null;
    }
  }

  private async performSessionRefresh(session: AuthSession): Promise<AuthSession> {
    if (!session.refreshToken) {
      throw new Error("The account session expired. Sign in again.");
    }
    const revision = this.sessionRevision;
    const refreshed = await this.client.refreshAccessToken(session.baseUrl, session.refreshToken);
    if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
    const updated = {
      ...session,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? session.refreshToken,
      ...(refreshed.expiresIn === undefined
        ? {}
        : { accessTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000 }),
    };
    await writeAuthSession(updated);
    return updated;
  }
}

interface PendingCapture {
  id: string;
  action: "save" | "update";
  name: string;
  url: string;
  username: string;
  password: string;
  updateId?: string;
  expiresAt: number;
  frameId: number;
  fingerprint: string;
  rememberUntil: number;
  dismissed?: boolean;
  saving?: boolean;
}

async function deriveMasterKey(
  password: string,
  email: string,
  kdf: KdfConfig,
): Promise<Uint8Array> {
  return kdf.type === KdfType.Pbkdf2Sha256
    ? derivePbkdf2MasterKey(password, email, kdf.iterations)
    : deriveArgon2idMasterKey(password, email, kdf);
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized || !normalized.includes("@") || /\s/.test(normalized)) {
    throw new Error("Enter a valid account email address.");
  }
  return normalized;
}

async function requireAccount(): Promise<AccountMetadata> {
  const account = await readAccountMetadata();
  if (!account) {
    throw new Error("No account is configured. Sign in first.");
  }
  return account;
}

async function requireSession() {
  const session = await readAuthSession();
  if (!session) {
    throw new Error("The account session has expired. Sign in again.");
  }
  return session;
}

function requireUserKey(value: number[] | undefined): Uint8Array {
  if (!value) {
    throw new Error("The vault is locked.");
  }
  const key = new Uint8Array(value);
  if (key.length !== 64) {
    throw new Error("The session account key is invalid.");
  }
  return key;
}
