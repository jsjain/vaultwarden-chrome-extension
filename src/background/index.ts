import { VaultwardenClient } from "../api/vaultwarden-client";
import { normalizeServerEnvironment } from "../shared/environment";
import {
  isExtensionRequest,
  type ExtensionRequest,
  type ExtensionResponse,
  type ResponseData,
} from "../shared/messages";
import { readAuthSession, writeAuthSession, writeServerSnapshot } from "../shared/storage";
import type { ServerSnapshot } from "../shared/storage-types";
import {
  isUrlExcluded,
  readBrowserIntegrationOptions,
  readGeneratorOptions,
  readVaultTimeoutMinutes,
  writeBrowserIntegrationOptions,
  writeGeneratorOptions,
  writeVaultTimeoutMinutes,
} from "../shared/settings";
import { generatePassword } from "../crypto/password-generator";
import { VaultController } from "./vault-controller";
import { configureSiteIntegration, restoreSiteIntegration, siteIntegrationEnabled } from "./site-integration";
import { isAutoLockAlarm, touchAutoLock } from "./auto-lock";

const client = new VaultwardenClient();
const controller = new VaultController();

void restoreSiteIntegration().catch(() => configureSiteIntegration(false));

void chrome.storage.session
  .setAccessLevel({ accessLevel: chrome.storage.AccessLevel.TRUSTED_CONTEXTS })
  .catch(() => undefined);

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !isExtensionRequest(message)) {
    return false;
  }
  void dispatch(message, sender)
    .then(async (data) => {
      const state = await controller.getState();
      await touchAutoLock(state.phase === "unlocked");
      sendResponse({ ok: true, data } satisfies ExtensionResponse);
    })
    .catch((error: unknown) => {
      sendResponse({ ok: false, error: publicError(error) } satisfies ExtensionResponse);
    });
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (isAutoLockAlarm(alarm)) void controller.lock();
});

async function dispatch(request: ExtensionRequest, sender: chrome.runtime.MessageSender): Promise<ResponseData> {
  switch (request.type) {
    case "app.getState":
      return { type: "state", state: await controller.getState() };
    case "server.check": {
      const environment = normalizeServerEnvironment(request.baseUrl);
      const server = await client.checkServer(environment.baseUrl);
      const snapshot: ServerSnapshot = {
        baseUrl: server.baseUrl,
        checkedAt: new Date().toISOString(),
        ...(server.serverVersion === undefined ? {} : { serverVersion: server.serverVersion }),
      };
      await writeServerSnapshot(snapshot);
      return { type: "server", snapshot };
    }
    case "auth.login":
      return { type: "login", result: await controller.login(request) };
    case "auth.sendEmailCode":
      await controller.sendTwoFactorEmail(request.baseUrl, request.email, request.masterPassword);
      return { type: "done" };
    case "auth.unlock": {
      const result = await controller.unlock(request.masterPassword);
      return { type: "unlock", ...result };
    }
    case "auth.lock":
      await controller.lock();
      return { type: "done" };
    case "auth.logout":
      await controller.logout();
      return { type: "done" };
    case "vault.sync":
      return { type: "sync", ...(await controller.sync()) };
    case "vault.list":
      return { type: "items", items: await controller.list(request) };
    case "vault.get":
      return { type: "item", item: await controller.detail(request.id, request.currentUrl) };
    case "vault.authorize":
      await controller.authorizeReprompt(request.id, request.masterPassword);
      return { type: "done" };
    case "vault.totp":
      return { type: "totp", ...(await controller.totp(request.id)) };
    case "vault.fill":
      return { type: "fill", ...(await controller.fill(request.id)) };
    case "vault.create":
      await controller.createLogin(request.login);
      return { type: "done" };
    case "vault.update":
      await controller.updateLogin(request.id, request.login);
      return { type: "done" };
    case "settings.get":
      return currentSettings();
    case "settings.siteIntegration":
      await configureSiteIntegration(request.enabled);
      if (!request.enabled) controller.clearPendingSiteLogins();
      return currentSettings();
    case "settings.vaultTimeout":
      {
      const session = await readAuthSession();
      await writeVaultTimeoutMinutes(request.minutes);
      if (session) await writeAuthSession(session);
      return currentSettings();
      }
    case "settings.browserOptions":
      await writeBrowserIntegrationOptions(request.options);
      return currentSettings();
    case "settings.generator":
      await writeGeneratorOptions(request.options);
      return currentSettings();
    case "site.suggestions": {
      await requireSiteIntegrationEnabled();
      requireSiteSender(sender, request.url);
      await requireSiteAllowed(request.url);
      return { type: "siteSuggestions", items: await controller.siteSuggestions(request.url) };
    }
    case "site.credential": {
      await requireSiteIntegrationEnabled();
      requireSiteSender(sender, request.url);
      await requireSiteAllowed(request.url);
      return { type: "siteCredential", ...(await controller.siteCredential(request.id, request.url)) };
    }
    case "site.inspect": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender, request.url);
      const options = await requireSiteAllowed(request.url);
      return {
        type: "sitePrompt",
        prompt: await controller.inspectSiteLogin(tabId, request.url, request.username, request.password, options),
      };
    }
    case "site.pendingPrompt": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender);
      await requireSiteAllowed(sender.url!);
      return { type: "sitePrompt", prompt: controller.pendingSitePrompt(tabId) };
    }
    case "site.generatePassword": {
      await requireSiteIntegrationEnabled();
      requireSiteSender(sender, request.url);
      await requireSiteAllowed(request.url);
      return { type: "generatedPassword", password: generatePassword(await readGeneratorOptions()) };
    }
    case "site.save": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender);
      await requireSiteAllowed(sender.url!);
      await controller.savePendingSiteLogin(tabId, request.promptId, request.login);
      return { type: "done" };
    }
    case "site.dismiss": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender);
      controller.dismissPendingSiteLogin(tabId, request.promptId);
      return { type: "done" };
    }
  }
}

async function currentSettings(): Promise<Extract<ResponseData, { type: "settings" }>> {
  const [integration, vaultTimeoutMinutes, browserOptions, generatorOptions] = await Promise.all([
    siteIntegrationEnabled(),
    readVaultTimeoutMinutes(),
    readBrowserIntegrationOptions(),
    readGeneratorOptions(),
  ]);
  return { type: "settings", siteIntegrationEnabled: integration, vaultTimeoutMinutes, browserOptions, generatorOptions };
}

async function requireSiteIntegrationEnabled(): Promise<void> {
  if (!(await siteIntegrationEnabled())) throw new Error("Website integration is disabled.");
}

async function requireSiteAllowed(url: string) {
  const options = await readBrowserIntegrationOptions();
  if (isUrlExcluded(url, options)) throw new Error("LeanVault is disabled for this domain.");
  return options;
}

function requireSiteSender(sender: chrome.runtime.MessageSender, requestedUrl?: string): number {
  if (sender.tab?.id === undefined || !sender.url || !/^https?:\/\//i.test(sender.url)) {
    throw new Error("This request must come from a website tab.");
  }
  if (requestedUrl) {
    let senderOrigin: string;
    let requestedOrigin: string;
    try {
      senderOrigin = new URL(sender.url).origin;
      requestedOrigin = new URL(requestedUrl).origin;
    } catch {
      throw new Error("The website URL is invalid.");
    }
    if (senderOrigin !== requestedOrigin) throw new Error("The website origin changed.");
  }
  return sender.tab.id;
}

function publicError(error: unknown): string {
  if (!(error instanceof Error)) {
    return "Unexpected extension error.";
  }
  if (/integrity|decrypt|master password/i.test(error.message)) {
    return "The vault could not be unlocked. Check the master password and account encryption settings.";
  }
  return error.message;
}
