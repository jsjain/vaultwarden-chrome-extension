import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VaultController } from "../src/background/vault-controller";
import { DEFAULT_BROWSER_INTEGRATION_OPTIONS as options } from "../src/shared/settings";
import { createEncryptedLogin } from "../src/vault/encrypt-login";
import type { SyncResponse } from "../src/api/models";

let encrypted: SyncResponse | null;
vi.mock("../src/shared/database", () => ({
  readEncryptedSync: async () => encrypted,
  writeEncryptedSync: async (payload: SyncResponse) => { encrypted = payload; },
  clearEncryptedSync: async () => { encrypted = null; },
}));
vi.mock("../src/shared/persistent-session", () => ({ clearPersistentAuthSession: async () => undefined }));
const key = new Uint8Array(64).fill(7);
let local: Record<string, unknown>;
let session: Record<string, unknown>;
let payload: SyncResponse;
let fetchMock: ReturnType<typeof vi.fn>;
const storage = (data: Record<string, unknown>) => ({
  get: async (name: string) => ({ [name]: data[name] }),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});
beforeEach(() => {
  local = { accountMetadata: { email: "test@example.com", baseUrl: "https://vault.example.com", itemCount: 0 }, serverSnapshot: { baseUrl: "https://vault.example.com" } };
  session = { authSession: { email: "test@example.com", baseUrl: "https://vault.example.com", accessToken: "test", userKey: [...key] } };
  encrypted = payload = { Ciphers: [] };
  vi.stubGlobal("chrome", { storage: { local: storage(local), session: storage(session) } });
  fetchMock = vi.fn(async () => new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

it("keeps one prompt and deadline across repeated submits and MFA navigation", async () => {
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com/login", "alice", "secret", options, 0);
  const again = await controller.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0);
  expect(again).toEqual(first);
  expect(first).toMatchObject({ expiresAt: expect.any(Number) });
  expect(await controller.pendingSitePrompt(1, "https://example.com/mfa", 0)).toEqual(first);
  expect(await controller.pendingSitePrompt(1, "https://evil.example/", 0)).toBeNull();
  expect(await controller.pendingSitePrompt(1, "https://example.com/mfa", 2)).toBeNull();
  expect(await controller.inspectSiteLogin(1, "https://example.com/login", "alice", "secret", options, 2)).toBeNull();
});

it("expires after ten seconds and suppresses the same login after a worker restart", async () => {
  vi.useFakeTimers();
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  expect(first?.expiresAt).toBe(Date.now() + 10_000);
  await vi.advanceTimersByTimeAsync(10_000);
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toBeNull();
  const restarted = new VaultController();
  expect(await restarted.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0)).toBeNull();
  expect(await restarted.inspectSiteLogin(1, "https://example.com", "alice", "changed", options, 0)).not.toBeNull();
});

it("persists a configured prompt, and dismisses it without re-prompting", async () => {
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", { ...options, savePromptTimeoutSeconds: 60 }, 0);
  expect(first!.expiresAt - Date.now()).toBeGreaterThan(59_000);
  const restarted = new VaultController();
  expect(await restarted.pendingSitePrompt(1, "https://example.com/mfa", 0)).toEqual(first);
  await restarted.dismissPendingSiteLogin(1, first!.id);
  expect(await restarted.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0)).toBeNull();
});

it("pulls a server password change into the cached vault", async () => {
  const controller = new VaultController();
  await controller.sync();
  payload = { Ciphers: [{ ...await createEncryptedLogin({ name: "Example", username: "alice", password: "new secret", uri: "https://example.com" }, key), Id: "login" }] };
  await controller.sync();
  expect(await controller.siteCredential("login", "https://example.com")).toEqual({ username: "alice", password: "new secret" });
});

it("does not repopulate decrypted credentials if locking interrupts sync", async () => {
  const controller = new VaultController();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => { started(); await waiting; return new Response(JSON.stringify({ Ciphers: [] }), { headers: { "content-type": "application/json" } }); });
  const syncing = controller.sync().catch(() => undefined);
  await began;
  await controller.lock();
  release();
  await syncing;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});

it("syncs ciphertext while locked without unlocking the vault", async () => {
  const controller = new VaultController();
  await controller.lock();
  payload = { Ciphers: [], Folders: [{ Id: "new folder" }] };
  await controller.sync();
  expect(encrypted).toEqual(payload);
  expect(await controller.getState()).toMatchObject({ phase: "locked", lastSync: expect.any(String) });
});

it("sends edits to the backend and performs a fresh sync after an older sync finishes", async () => {
  const login = { name: "Example", username: "alice", password: "old secret", uri: "https://example.com" };
  const raw = { ...await createEncryptedLogin(login, key), Id: "login" };
  payload = { Ciphers: [raw] };
  const controller = new VaultController();
  await controller.sync();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  let written!: () => void;
  const saved = new Promise<void>((resolve) => { written = resolve; });
  const requests: string[] = [];
  let holdNextSync = true;
  fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
    requests.push(`${init.method} ${url}`);
    let body: unknown = payload;
    if (init.method === "PUT") {
      payload = { Ciphers: [{ ...JSON.parse(init.body as string), Id: "login" }] };
      body = payload;
      written();
    } else if (url.endsWith("/ciphers/login")) body = raw;
    else if (holdNextSync) { holdNextSync = false; started(); await waiting; }
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  const background = controller.sync();
  await began;
  const editing = controller.updateLogin("login", { ...login, password: "new secret" });
  await saved;
  release();
  await Promise.all([background, editing]);
  expect(requests.at(-1)).toBe("GET https://vault.example.com/api/sync?excludeDomains=true");
  expect(await controller.siteCredential("login", "https://example.com")).toEqual({ username: "alice", password: "new secret" });
});

it("retains a pending login after a failed write so saving can be retried", async () => {
  const controller = new VaultController();
  const prompt = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  fetchMock.mockRejectedValueOnce(new Error("offline"));
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).rejects.toThrow();
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toEqual(prompt);
});

it("refreshes an expired token once when a sync and edit run together", async () => {
  const login = { name: "Example", username: "alice", password: "secret", uri: "https://example.com" };
  const raw = { ...await createEncryptedLogin(login, key), Id: "login" };
  payload = { Ciphers: [raw] };
  const controller = new VaultController();
  await controller.sync();
  Object.assign(session.authSession as object, { refreshToken: "refresh", accessTokenExpiresAt: 0 });
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let refreshes = 0;
  fetchMock.mockImplementation(async (url: string) => {
    let body: unknown = url.endsWith("/ciphers/login") ? raw : payload;
    if (url.endsWith("/connect/token")) {
      refreshes++;
      await waiting;
      body = { access_token: "new token", refresh_token: "new refresh", expires_in: 3600 };
    }
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  const tasks = Promise.all([controller.sync(), controller.updateLogin("login", login)]);
  await vi.waitFor(() => expect(refreshes).toBeGreaterThan(0));
  release();
  await tasks;
  expect(refreshes).toBe(1);
});

it("does not restore decrypted credentials when a write finishes after locking", async () => {
  const controller = new VaultController();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => {
    started();
    await waiting;
    return new Response("{}", { headers: { "content-type": "application/json" } });
  });
  const saving = controller.createLogin({ name: "Example", username: "alice", password: "secret", uri: "https://example.com" });
  await began;
  await controller.lock();
  release();
  await saving;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});

it("consumes a committed save even if the following refresh fails", async () => {
  const controller = new VaultController();
  const prompt = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  fetchMock.mockResolvedValueOnce(new Response("{}", { headers: { "content-type": "application/json" } })).mockRejectedValueOnce(new Error("offline"));
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).resolves.toBeUndefined();
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toBeNull();
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).rejects.toThrow("expired");
});

it("blocks a sync that starts while lock is clearing pending prompt storage", async () => {
  const controller = new VaultController();
  let finishCleanup!: () => void;
  const cleanup = new Promise<void>((resolve) => { finishCleanup = resolve; });
  let cleanupStarted!: () => void;
  const clearing = new Promise<void>((resolve) => { cleanupStarted = resolve; });
  const originalSet = chrome.storage.session.set;
  vi.spyOn(chrome.storage.session, "set").mockImplementation(async (values) => {
    if ("pendingSiteLogins" in values) { cleanupStarted(); await cleanup; }
    await originalSet(values);
  });
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => {
    started(); await waiting;
    return new Response('{"Ciphers":[]}', { headers: { "content-type": "application/json" } });
  });
  const locking = controller.lock();
  await clearing;
  const syncing = controller.sync().catch(() => undefined);
  await began;
  finishCleanup();
  await locking;
  release();
  await syncing;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});
