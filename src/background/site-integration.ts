const SCRIPT_ID = "leanvault-site-integration";
const STORAGE_KEY = "leanvault.siteIntegrationEnabled";

export async function siteIntegrationEnabled(): Promise<boolean> {
  const value = await chrome.storage.local.get(STORAGE_KEY);
  return value[STORAGE_KEY] === true;
}

export async function configureSiteIntegration(enabled: boolean): Promise<void> {
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] });
  if (existing.length > 0) await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
  if (enabled) {
    const granted = await chrome.permissions.contains({ origins: ["https://*/*", "http://*/*"] });
    if (!granted) throw new Error("Website access was not granted.");
    await chrome.scripting.registerContentScripts([
      {
        id: SCRIPT_ID,
        js: ["site.js"],
        matches: ["https://*/*", "http://*/*"],
        allFrames: true,
        runAt: "document_idle",
        persistAcrossSessions: true,
      },
    ]);
  }
  await chrome.storage.local.set({ [STORAGE_KEY]: enabled });
}

export async function restoreSiteIntegration(): Promise<void> {
  if (await siteIntegrationEnabled()) await configureSiteIntegration(true);
}
