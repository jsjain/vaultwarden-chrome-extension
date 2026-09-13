// Run with PLAYWRIGHT_MODULE pointing to an installed playwright-core index.mjs.
import assert from "node:assert/strict";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright-core");
const bundle = await build({ entryPoints: ["src/site/index.ts"], bundle: true, write: false, format: "iife" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  for (const dismissSelector of [".dismiss", ".close"]) {
    const page = await browser.newPage();
    await page.route("https://example.com/**", (route) => route.fulfill({ contentType: "text/html", body: '<form><input name="username" autocomplete="username" value="alice"><input type="password" value="secret"><button>Sign in</button></form>' }));
    await page.goto("https://example.com/login");
    await page.clock.install({ time: new Date("2030-01-01T00:00:00Z") });
    await page.clock.pauseAt(new Date("2030-01-01T00:00:00Z"));
    await page.evaluate(() => {
      window.messages = [];
      window.promptSeconds = 10;
      window.chrome = { storage: { onChanged: { addListener: (listener) => { window.siteStorageListener = listener; } } }, runtime: { sendMessage: async (message) => {
        window.messages.push(message);
        if (message.type === "site.save" && window.failSave) return { ok: false, error: "offline" };
        let data = { type: "done" };
        if (message.type === "site.suggestions") data = { type: "siteSuggestions", items: [] };
        if (message.type === "site.pendingPrompt") data = { type: "sitePrompt", prompt: null };
        if (message.type === "site.inspect") data = { type: "sitePrompt", prompt: {
          id: "prompt", action: "save", name: "Example", username: message.username,
          password: message.password, uri: message.url, expiresAt: Date.now() + window.promptSeconds * 1000,
        } };
        return { ok: true, data };
      } } };
      document.querySelector("form").addEventListener("submit", (event) => event.preventDefault());
    });
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    await page.locator("form > button").click();
    await page.locator("#leanvault-save-prompt").waitFor();
    await page.clock.runFor(3_100);
    await page.locator(`#leanvault-save-prompt ${dismissSelector}`).click();
    await page.waitForTimeout(50);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 0, `${dismissSelector} must dismiss on the first click`);
    assert.equal(await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length), 1, "prompt controls must not capture credentials");
    await page.locator("form > button").click();
    await page.locator("#leanvault-save-prompt").waitFor();
    await page.clock.runFor(9_999);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 1);
    await page.clock.runFor(1);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 0, "default timeout must dismiss after ten seconds");
    await page.evaluate(() => { window.promptSeconds = 30; });
    await page.locator("form > button").click();
    await page.locator("#leanvault-save-prompt").waitFor();
    await page.locator("#leanvault-save-prompt .prompt-username").fill("edited");
    assert.equal(await page.locator("#leanvault-field-menu").count(), 0, "prompt fields must not open autofill menus");
    await page.clock.runFor(10_000);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 1);
    await page.clock.runFor(20_000);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 0, "configured timeout must be honored");
    await page.evaluate(() => { window.promptSeconds = 10; window.failSave = true; });
    await page.locator("form > button").click();
    await page.locator("#leanvault-save-prompt").waitFor();
    await page.locator("#leanvault-save-prompt .save").click();
    await page.clock.runFor(10_000);
    assert.equal(await page.locator("#leanvault-save-prompt").count(), 0, "failed saves must restore auto-dismissal");
    const capturesBeforeMfa = await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length);
    await page.evaluate(() => {
      const form = document.querySelector("form");
      form.innerHTML = '<input type="password" autocomplete="one-time-code" value="123456"><button>Verify</button>';
    });
    await page.locator("form > button").click();
    assert.equal(await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length), capturesBeforeMfa, "MFA codes must not be captured as new passwords");
    await page.close();
  }
  const popup = await browser.newPage();
  const html = (await readFile("src/popup/index.html", "utf8")).replace(/<script[^>]*>[\s\S]*?<\/script>/g, "");
  await popup.route("https://extension.test/**", (route) => route.fulfill({ contentType: "text/html", body: html }));
  await popup.goto("https://extension.test/");
  await popup.evaluate(() => {
    window.itemName = "Before sync";
    window.syncListener = () => {};
    window.chrome = {
      tabs: { query: async () => [] },
      storage: { onChanged: { addListener: (listener) => { window.syncListener = listener; } } },
      runtime: {
        getManifest: () => ({ version: "1.0.2" }),
        getURL: (path) => `https://extension.test${path}`,
        sendMessage: async (message) => {
          let data;
          if (message.type === "settings.get") data = {
            type: "settings", siteIntegrationEnabled: true, vaultTimeoutMinutes: 0,
            browserOptions: { askAddLogin: true, askUpdateLogin: true, savePromptTimeoutSeconds: 10, excludedDomains: [] },
            generatorOptions: { length: 22, uppercase: true, lowercase: true, numbers: true, symbols: true },
          };
          if (message.type === "app.getState") data = { type: "state", state: {
            phase: "unlocked", snapshot: { baseUrl: "https://vault.example.com" }, email: "alice@example.com", itemCount: 1, decryptionFailures: 0,
          } };
          if (message.type === "vault.list") data = { type: "items", items: [{ id: "login", name: window.itemName, username: "alice", favorite: false, requiresReprompt: false, editable: true, matched: false }] };
          return { ok: true, data };
        },
      },
    };
  });
  const popupBundle = await build({ entryPoints: ["src/popup/index.ts"], bundle: true, write: false, format: "iife" });
  await popup.addScriptTag({ content: popupBundle.outputFiles[0].text });
  await popup.getByText("Before sync", { exact: true }).waitFor();
  await popup.evaluate(() => { window.itemName = "After sync"; window.syncListener({ accountMetadata: { newValue: { lastSync: "new" } } }, "local"); });
  await popup.getByText("After sync", { exact: true }).waitFor({ timeout: 2_000 });
  await popup.locator("#add-login").click();
  await popup.locator("#login-name").fill("Unsaved draft");
  await popup.evaluate(() => window.syncListener({ accountMetadata: { newValue: { lastSync: "newer" } } }, "local"));
  assert.equal(await popup.locator("#login-name").inputValue(), "Unsaved draft");
  assert.equal(await popup.locator("#editor-view").isVisible(), true, "background sync must preserve the editor");
  await popup.close();
  console.log("Browser checks passed: popup refresh preserves drafts; first-click dismissal, isolated prompt controls, default and configured timeouts.");
} finally {
  await browser.close();
}
