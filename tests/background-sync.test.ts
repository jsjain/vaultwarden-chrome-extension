import { afterEach, expect, it, vi } from "vitest";
import { VaultController } from "../src/background/vault-controller";
vi.mock("../src/shared/persistent-session", () => ({ clearPersistentAuthSession: async () => undefined }));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.resetModules(); });

it("restores the minute alarm and syncs without touching the inactivity alarm", async () => {
  const alarmListeners: ((alarm: chrome.alarms.Alarm) => void)[] = [];
  const alarms = new Map<string, { periodInMinutes?: number }>();
  const cleared: string[] = [];
  vi.stubGlobal("chrome", {
    storage: {
      local: { get: async () => ({}) },
      session: { get: async () => ({}), setAccessLevel: async () => undefined },
      AccessLevel: { TRUSTED_CONTEXTS: "TRUSTED_CONTEXTS" },
    },
    runtime: { onMessage: { addListener: () => undefined } },
    tabs: { onRemoved: { addListener: () => undefined } },
    alarms: {
      get: async (name: string) => alarms.get(name),
      create: async (name: string, info: { periodInMinutes?: number }) => { alarms.set(name, info); },
      clear: async (name: string) => { cleared.push(name); },
      onAlarm: { addListener: (listener: (alarm: chrome.alarms.Alarm) => void) => alarmListeners.push(listener) },
    },
  });
  vi.spyOn(VaultController.prototype, "getState").mockResolvedValue({ phase: "unlocked" } as Awaited<ReturnType<VaultController["getState"]>>);
  const sync = vi.spyOn(VaultController.prototype, "sync").mockResolvedValue({ itemCount: 1, failures: 0 });
  await import("../src/background/index");
  await vi.waitFor(() => expect(alarms.get("leanvault-sync")?.periodInMinutes).toBe(1));
  for (const listener of alarmListeners) listener({ name: "leanvault-sync", scheduledTime: Date.now(), persistAcrossSessions: false });
  await vi.waitFor(() => expect(sync).toHaveBeenCalledOnce());
  expect(cleared).toEqual([]);
});
