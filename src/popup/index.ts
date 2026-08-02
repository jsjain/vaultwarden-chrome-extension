import { normalizeServerEnvironment } from "../shared/environment";
import { generatePassword } from "../crypto/password-generator";
import type {
  ExtensionRequest,
  ExtensionResponse,
  PublicAppState,
  ResponseData,
} from "../shared/messages";
import { isVaultTimeoutMinutes, type VaultTimeoutMinutes } from "../shared/settings";
import type { VaultItemDetail, VaultItemSummary } from "../vault/models";

const views = {
  setup: element<HTMLElement>("setup-view"),
  login: element<HTMLElement>("login-view"),
  locked: element<HTMLElement>("locked-view"),
  vault: element<HTMLElement>("vault-view"),
  generator: element<HTMLElement>("generator-view"),
  settings: element<HTMLElement>("settings-view"),
  detail: element<HTMLElement>("detail-view"),
  editor: element<HTMLElement>("editor-view"),
};
const appTitle = element<HTMLHeadingElement>("app-title");
const brandMark = element<HTMLSpanElement>("brand-mark");
const statePill = element<HTMLSpanElement>("state-pill");
const subtitle = element<HTMLParagraphElement>("subtitle");
const addLogin = element<HTMLButtonElement>("add-login");
const accountAvatar = element<HTMLButtonElement>("account-avatar");
const bottomNav = element<HTMLElement>("bottom-nav");
const navVault = element<HTMLButtonElement>("nav-vault");
const navGenerator = element<HTMLButtonElement>("nav-generator");
const status = element<HTMLParagraphElement>("status");
const serverForm = element<HTMLFormElement>("server-form");
const serverUrl = element<HTMLInputElement>("server-url");
const serverSubmit = element<HTMLButtonElement>("server-submit");
const serverDetail = element<HTMLParagraphElement>("server-detail");
const changeServer = element<HTMLButtonElement>("change-server");
const loginForm = element<HTMLFormElement>("login-form");
const email = element<HTMLInputElement>("email");
const masterPassword = element<HTMLInputElement>("master-password");
const loginSubmit = element<HTMLButtonElement>("login-submit");
const twoFactorFields = element<HTMLFieldSetElement>("two-factor-fields");
const twoFactorProvider = element<HTMLSelectElement>("two-factor-provider");
const sendEmailCode = element<HTMLButtonElement>("send-email-code");
const twoFactorToken = element<HTMLInputElement>("two-factor-token");
const twoFactorRemember = element<HTMLInputElement>("two-factor-remember");
const deviceFields = element<HTMLFieldSetElement>("device-fields");
const deviceOtp = element<HTMLInputElement>("device-otp");
const unlockForm = element<HTMLFormElement>("unlock-form");
const unlockPassword = element<HTMLInputElement>("unlock-password");
const unlockSubmit = element<HTMLButtonElement>("unlock-submit");
const lockedAccount = element<HTMLParagraphElement>("locked-account");
const search = element<HTMLInputElement>("search");
const itemList = element<HTMLDivElement>("item-list");
const emptyState = element<HTMLParagraphElement>("empty-state");
const vaultContext = element<HTMLParagraphElement>("vault-context");
const detailName = element<HTMLHeadingElement>("detail-name");
const detailUri = element<HTMLParagraphElement>("detail-uri");
const detailUsername = element<HTMLSpanElement>("detail-username");
const detailPassword = element<HTMLSpanElement>("detail-password");
const detailTotp = element<HTMLSpanElement>("detail-totp");
const totpRow = element<HTMLDivElement>("totp-row");
const passwordRow = element<HTMLDivElement>("password-row");
const fillDetail = element<HTMLButtonElement>("fill-detail");
const repromptForm = element<HTMLFormElement>("reprompt-form");
const repromptPassword = element<HTMLInputElement>("reprompt-password");
const repromptSubmit = element<HTMLButtonElement>("reprompt-submit");
const editorForm = element<HTMLFormElement>("editor-form");
const editorTitle = element<HTMLHeadingElement>("editor-title");
const loginName = element<HTMLInputElement>("login-name");
const loginUsername = element<HTMLInputElement>("login-username");
const loginPassword = element<HTMLInputElement>("login-password");
const loginUri = element<HTMLInputElement>("login-uri");
const loginNotes = element<HTMLTextAreaElement>("login-notes");
const loginFavorite = element<HTMLInputElement>("login-favorite");
const editorSubmit = element<HTMLButtonElement>("editor-submit");
const editLogin = element<HTMLButtonElement>("edit-login");
const siteAccess = element<HTMLButtonElement>("site-access");
const vaultTimeout = element<HTMLSelectElement>("vault-timeout");
const settingsAccount = element<HTMLParagraphElement>("settings-account");
const settingsServer = element<HTMLParagraphElement>("settings-server");
const appVersion = element<HTMLParagraphElement>("app-version");
const generatorOutput = element<HTMLInputElement>("generator-output");
const generatorLength = element<HTMLInputElement>("generator-length");
const generatorLengthValue = element<HTMLOutputElement>("generator-length-value");
const generatorUppercase = element<HTMLInputElement>("generator-uppercase");
const generatorLowercase = element<HTMLInputElement>("generator-lowercase");
const generatorNumbers = element<HTMLInputElement>("generator-numbers");
const generatorSymbols = element<HTMLInputElement>("generator-symbols");

let currentUrl: string | undefined;
let selectedItem: VaultItemDetail | null = null;
let editingId: string | null = null;
let siteIntegrationEnabled = false;
let vaultTimeoutMinutes: VaultTimeoutMinutes = 0;
let totalItems = 0;

void initialize().catch(showError);

serverForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void verifyServer();
});
loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void login();
});
unlockForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void unlock();
});
repromptForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void authorizeReprompt();
});
editorForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveEditor();
});
changeServer.addEventListener("click", () => showView("setup"));
element("locked-logout").addEventListener("click", () => void logout());
element("logout").addEventListener("click", () => void logout());
element("lock").addEventListener("click", () => void lock());
element("sync").addEventListener("click", () => void syncVault());
addLogin.addEventListener("click", () => openEditor());
accountAvatar.addEventListener("click", () => showView("settings"));
navVault.addEventListener("click", () => {
  showView("vault");
  void loadItems();
});
navGenerator.addEventListener("click", () => {
  showView("generator");
  refreshGeneratedPassword();
});
siteAccess.addEventListener("click", () => void toggleSiteIntegration());
vaultTimeout.addEventListener("change", () => void updateVaultTimeout());
editLogin.addEventListener("click", () => selectedItem && openEditor(selectedItem));
element("editor-back").addEventListener("click", () => {
  editingId ? void showDetail(editingId) : showView("vault");
});
element("generate-password").addEventListener("click", () => {
  loginPassword.value = defaultGeneratedPassword();
  loginPassword.focus();
  loginPassword.select();
});
element("generator-refresh").addEventListener("click", refreshGeneratedPassword);
element("generator-copy").addEventListener("click", () =>
  void copySecret(generatorOutput.value, "Generated password copied."),
);
element("generator-use").addEventListener("click", () => {
  const password = generatorOutput.value;
  openEditor();
  loginPassword.value = password;
});
for (const input of [
  generatorLength,
  generatorUppercase,
  generatorLowercase,
  generatorNumbers,
  generatorSymbols,
]) {
  input.addEventListener("input", refreshGeneratedPassword);
}
element("detail-back").addEventListener("click", () => {
  selectedItem = null;
  showView("vault");
});
fillDetail.addEventListener("click", () => selectedItem && void fill(selectedItem.id));
element("copy-username").addEventListener("click", () =>
  selectedItem && void copySecret(selectedItem.username, "Username copied."),
);
element("copy-password").addEventListener("click", () =>
  selectedItem && void copySecret(selectedItem.password, "Password copied."),
);
element("copy-totp").addEventListener("click", () => void copyTotp());
twoFactorProvider.addEventListener("change", updateTwoFactorControls);
sendEmailCode.addEventListener("click", () => void requestEmailCode());
element("reveal-password").addEventListener("click", () => {
  const hidden = detailPassword.classList.toggle("password-mask");
  element<HTMLButtonElement>("reveal-password").textContent = hidden ? "Show" : "Hide";
});
search.addEventListener("input", () => void loadItems());

async function initialize(): Promise<void> {
  appVersion.textContent = `LeanVault ${chrome.runtime.getManifest().version}`;
  currentUrl = await activeTabUrl();
  refreshGeneratedPassword();
  await refreshSettings();
  await refreshState();
}

async function refreshSettings(): Promise<void> {
  const data = await request({ type: "settings.get" });
  if (data.type !== "settings") return;
  siteIntegrationEnabled = data.siteIntegrationEnabled;
  vaultTimeoutMinutes = data.vaultTimeoutMinutes;
  vaultTimeout.value = String(vaultTimeoutMinutes);
  updateSiteAccessButton();
}

async function toggleSiteIntegration(): Promise<void> {
  try {
    const enabled = !siteIntegrationEnabled;
    if (enabled) {
      const granted = await chrome.permissions.request({ origins: ["https://*/*", "http://*/*"] });
      if (!granted) throw new Error("Website access was not granted.");
    }
    const data = await request({ type: "settings.siteIntegration", enabled });
    if (data.type !== "settings") throw new Error("The background worker returned invalid settings.");
    siteIntegrationEnabled = data.siteIntegrationEnabled;
    vaultTimeoutMinutes = data.vaultTimeoutMinutes;
    updateSiteAccessButton();
    showStatus(siteIntegrationEnabled ? "Website autofill and save prompts enabled." : "Website prompts disabled.", "success");
  } catch (error) {
    showError(error);
  }
}

function updateSiteAccessButton(): void {
  siteAccess.textContent = siteIntegrationEnabled ? "Enabled" : "Enable";
  siteAccess.title = siteIntegrationEnabled ? "Disable website integration" : "Enable website integration";
}

async function updateVaultTimeout(): Promise<void> {
  try {
    const minutes = Number(vaultTimeout.value);
    if (!isVaultTimeoutMinutes(minutes)) throw new Error("Unsupported vault timeout.");
    const data = await request({ type: "settings.vaultTimeout", minutes });
    if (data.type !== "settings") throw new Error("The background worker returned invalid settings.");
    vaultTimeoutMinutes = data.vaultTimeoutMinutes;
    vaultTimeout.value = String(vaultTimeoutMinutes);
    showStatus(timeoutConfirmation(vaultTimeoutMinutes), "success");
  } catch (error) {
    vaultTimeout.value = String(vaultTimeoutMinutes);
    showError(error);
  }
}

function timeoutConfirmation(minutes: VaultTimeoutMinutes): string {
  if (minutes === -1) return "Vault will stay unlocked on this browser until you lock or log out.";
  if (minutes === 0) return "Vault will remain unlocked until the browser closes.";
  return `Vault will lock after ${minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hour${minutes === 60 ? "" : "s"}`} of inactivity.`;
}

async function refreshState(): Promise<void> {
  const data = await request({ type: "app.getState" });
  if (data.type !== "state") {
    throw new Error("The background worker returned an invalid state response.");
  }
  renderState(data.state);
}

function renderState(state: PublicAppState): void {
  clearStatus();
  switch (state.phase) {
    case "setup":
      markState("Not connected", "neutral");
      subtitle.textContent = "Connect a Vaultwarden server";
      showView("setup");
      break;
    case "signed-out":
      serverUrl.value = state.snapshot.baseUrl;
      email.value = state.email ?? "";
      serverDetail.textContent = serverLabel(state.snapshot.baseUrl, state.snapshot.serverVersion);
      markState("Signed out", "neutral");
      subtitle.textContent = state.snapshot.baseUrl;
      showView("login");
      break;
    case "locked":
      totalItems = state.itemCount;
      serverUrl.value = state.snapshot.baseUrl;
      lockedAccount.textContent = `${state.email} · ${state.itemCount} logins`;
      markState("Locked", "neutral");
      subtitle.textContent = state.email;
      showView("locked");
      unlockPassword.focus();
      break;
    case "unlocked":
      totalItems = state.itemCount;
      serverUrl.value = state.snapshot.baseUrl;
      markState("Unlocked", "success");
      subtitle.textContent = state.email;
      accountAvatar.textContent = accountInitials(state.email);
      accountAvatar.title = `Settings for ${state.email}`;
      settingsAccount.textContent = state.email;
      settingsServer.textContent = state.snapshot.baseUrl;
      vaultContext.textContent = currentUrl
        ? `${state.itemCount} logins · suggestions for this page first`
        : `${state.itemCount} logins`;
      if (state.decryptionFailures > 0) {
        showStatus(`${state.decryptionFailures} unsupported or damaged item(s) were skipped.`, "error");
      }
      showView("vault");
      void loadItems();
      break;
  }
}

async function verifyServer(): Promise<void> {
  setBusy(serverSubmit, true, "Verifying…");
  clearStatus();
  try {
    const environment = normalizeServerEnvironment(serverUrl.value);
    const granted = await chrome.permissions.request({ origins: [environment.originPattern] });
    if (!granted) {
      throw new Error("Server permission was not granted.");
    }
    const data = await request({ type: "server.check", baseUrl: environment.baseUrl });
    if (data.type !== "server") {
      throw new Error("The background worker returned an invalid server response.");
    }
    serverDetail.textContent = serverLabel(data.snapshot.baseUrl, data.snapshot.serverVersion);
    subtitle.textContent = data.snapshot.baseUrl;
    markState("Signed out", "neutral");
    showView("login");
    email.focus();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(serverSubmit, false, "Verify server");
  }
}

async function login(): Promise<void> {
  setBusy(loginSubmit, true, "Signing in…");
  clearStatus();
  try {
    const data = await request({
      type: "auth.login",
      baseUrl: normalizeServerEnvironment(serverUrl.value).baseUrl,
      email: email.value,
      masterPassword: masterPassword.value,
      ...(twoFactorFields.hidden ? {} : { twoFactorProvider: Number(twoFactorProvider.value) }),
      ...(twoFactorToken.value ? { twoFactorToken: twoFactorToken.value } : {}),
      ...(twoFactorFields.hidden ? {} : { twoFactorRemember: twoFactorRemember.checked }),
      ...(deviceOtp.value ? { newDeviceOtp: deviceOtp.value } : {}),
    });
    if (data.type !== "login") {
      throw new Error("The background worker returned an invalid login response.");
    }
    if (data.result.status === "two-factor") {
      populateTwoFactor(data.result.providers);
      twoFactorFields.hidden = false;
      twoFactorToken.required = true;
      showStatus("Enter your two-step login code.", "neutral");
      twoFactorToken.focus();
      return;
    }
    if (data.result.status === "device-verification") {
      deviceFields.hidden = false;
      deviceOtp.required = true;
      showStatus(data.result.message, "neutral");
      deviceOtp.focus();
      return;
    }
    masterPassword.value = "";
    twoFactorToken.value = "";
    deviceOtp.value = "";
    await refreshState();
    showStatus(`Vault unlocked with ${data.result.itemCount} logins.`, "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(loginSubmit, false, "Sign in and sync");
  }
}

async function unlock(): Promise<void> {
  setBusy(unlockSubmit, true, "Unlocking…");
  try {
    const data = await request({ type: "auth.unlock", masterPassword: unlockPassword.value });
    if (data.type !== "unlock") {
      throw new Error("The background worker returned an invalid unlock response.");
    }
    unlockPassword.value = "";
    await refreshState();
    showStatus(`Vault unlocked with ${data.itemCount} logins.`, "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(unlockSubmit, false, "Unlock");
  }
}

async function loadItems(): Promise<void> {
  try {
    const data = await request({
      type: "vault.list",
      query: search.value,
      ...(currentUrl ? { currentUrl } : {}),
    });
    if (data.type !== "items") {
      throw new Error("The background worker returned an invalid vault list.");
    }
    renderItems(data.items);
  } catch (error) {
    showError(error);
  }
}

function renderItems(items: VaultItemSummary[]): void {
  itemList.replaceChildren();
  emptyState.hidden = items.length > 0;
  const matches = items.filter((item) => item.matched);
  const remaining = items.filter((item) => !item.matched);
  if (matches.length > 0) appendItemSection("Autofill suggestions", matches, matches.length);
  if (remaining.length > 0) {
    appendItemSection(search.value ? "Other results" : "All items", remaining, search.value ? remaining.length : totalItems);
  }
}

function appendItemSection(title: string, items: VaultItemSummary[], count: number): void {
  const section = document.createElement("section");
  section.className = "item-section";
  const heading = document.createElement("div");
  heading.className = "item-section-heading";
  const label = document.createElement("h2");
  label.textContent = title;
  const itemCount = document.createElement("span");
  itemCount.className = "item-count";
  itemCount.textContent = String(count);
  heading.append(label, itemCount);
  const group = document.createElement("div");
  group.className = "item-group";
  section.append(heading, group);
  let rendered = 0;
  const appendBatch = () => {
    const next = items.slice(rendered, rendered + 100);
    group.append(...next.map(createItemRow));
    rendered += next.length;
  };
  appendBatch();
  if (rendered < items.length) {
    const sentinel = document.createElement("span");
    sentinel.className = "item-sentinel";
    sentinel.setAttribute("aria-hidden", "true");
    section.append(sentinel);
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      appendBatch();
      if (rendered >= items.length) {
        observer.disconnect();
        sentinel.remove();
      }
    });
    observer.observe(sentinel);
  }
  itemList.append(section);
}

function createItemRow(item: VaultItemSummary): HTMLElement {
  const row = document.createElement("article");
  row.className = "item";
  row.setAttribute("role", "listitem");

  const icon = document.createElement("span");
  icon.className = "item-icon";
  icon.textContent = item.name.trim().charAt(0).toLocaleUpperCase() || "•";
  const favicon = siteFavicon(item.uri);
  if (favicon) icon.append(favicon);

  const main = document.createElement("div");
  main.className = "item-main";
  main.tabIndex = 0;
  const name = document.createElement("div");
  name.className = "item-name truncate";
  name.textContent = `${item.favorite ? "★ " : ""}${item.name}`;
  if (item.matched) {
    const dot = document.createElement("span");
    dot.className = "match-dot";
    dot.textContent = "●";
    dot.title = "Matches this page";
    name.append(dot);
  }
  const meta = document.createElement("div");
  meta.className = "item-meta truncate";
  meta.textContent = item.username || item.uri || "Login";
  main.append(name, meta);
  const open = () => void showDetail(item.id);
  main.addEventListener("click", open);
  main.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open();
    }
  });

  const actions = document.createElement("div");
  actions.className = "row-actions";
  if (item.matched) {
    const fillButton = document.createElement("button");
    fillButton.className = "fill-button";
    fillButton.type = "button";
    fillButton.textContent = item.requiresReprompt ? "Open" : "Fill";
    fillButton.addEventListener("click", () =>
      item.requiresReprompt ? void showDetail(item.id) : void fill(item.id),
    );
    actions.append(fillButton);
  }
  actions.append(rowIconButton("⧉", "Copy password", () => void copyItemPassword(item.id)));

  const menu = document.createElement("div");
  menu.className = "item-menu";
  menu.hidden = true;
  menu.append(
    itemAction("Copy username", () => void copySecret(item.username, "Username copied.")),
    itemAction("Copy password", () => void copyItemPassword(item.id)),
  );
  if (item.editable) menu.append(itemAction("Edit", () => void editItem(item.id)));
  actions.append(
    rowIconButton("⋮", "More actions", () => {
      closeItemMenus(menu);
      menu.hidden = !menu.hidden;
    }),
  );
  row.append(icon, main, actions, menu);
  return row;
}

function siteFavicon(uri?: string): HTMLImageElement | null {
  if (!uri) return null;
  try {
    const pageUrl = new URL(uri);
    if (pageUrl.protocol !== "http:" && pageUrl.protocol !== "https:") return null;
    const faviconUrl = new URL(chrome.runtime.getURL("/_favicon/"));
    faviconUrl.searchParams.set("pageUrl", pageUrl.href);
    faviconUrl.searchParams.set("size", "32");
    const image = document.createElement("img");
    image.src = faviconUrl.href;
    image.alt = "";
    image.loading = "lazy";
    image.addEventListener("error", () => image.remove());
    return image;
  } catch {
    return null;
  }
}

function closeItemMenus(except?: HTMLElement): void {
  for (const menu of itemList.querySelectorAll<HTMLElement>(".item-menu")) {
    if (menu !== except) menu.hidden = true;
  }
}

async function showDetail(id: string): Promise<void> {
  try {
    renderDetail(await getItemDetail(id));
  } catch (error) {
    showError(error);
  }
}

async function getItemDetail(id: string): Promise<VaultItemDetail> {
  const data = await request({ type: "vault.get", id, ...(currentUrl ? { currentUrl } : {}) });
  if (data.type !== "item") {
    throw new Error("The background worker returned an invalid vault item.");
  }
  return data.item;
}

function renderDetail(item: VaultItemDetail): void {
  selectedItem = item;
  detailName.textContent = item.name;
  detailUri.textContent = item.uri ?? "No website saved";
  detailUsername.textContent = item.username || "—";
  detailPassword.textContent = item.password || "—";
  detailPassword.classList.add("password-mask");
  repromptForm.hidden = !item.protected;
  passwordRow.hidden = item.protected;
  fillDetail.hidden = item.protected;
  totpRow.hidden = !item.hasTotp;
  editLogin.hidden = !item.editable || item.protected;
  detailTotp.textContent = item.hasTotp ? "Loading…" : "";
  element<HTMLButtonElement>("reveal-password").textContent = "Show";
  showView("detail");
  if (item.protected) {
    repromptPassword.focus();
  }
  if (item.hasTotp) {
    void refreshTotp();
  }
}

function itemAction(label: string, action: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

function rowIconButton(glyph: string, label: string, action: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.className = "row-icon-button";
  button.type = "button";
  button.textContent = glyph;
  button.title = label;
  button.setAttribute("aria-label", label);
  button.addEventListener("click", action);
  return button;
}

async function copyItemPassword(id: string): Promise<void> {
  try {
    const item = await getItemDetail(id);
    if (item.protected) {
      renderDetail(item);
      showStatus("Confirm your master password before copying this password.", "neutral");
      return;
    }
    await copySecret(item.password, "Password copied.");
  } catch (error) {
    showError(error);
  }
}

async function editItem(id: string): Promise<void> {
  try {
    const item = await getItemDetail(id);
    if (!item.editable) {
      throw new Error("Editing organization-owned logins is not supported yet.");
    }
    if (item.protected) {
      renderDetail(item);
      showStatus("Confirm your master password before editing this login.", "neutral");
      return;
    }
    selectedItem = item;
    openEditor(item);
  } catch (error) {
    showError(error);
  }
}

function openEditor(item?: VaultItemDetail): void {
  editingId = item?.id ?? null;
  editorTitle.textContent = item ? "Edit login" : "Add login";
  loginName.value = item?.name ?? suggestedSiteName();
  loginUsername.value = item?.username ?? "";
  loginPassword.value = item?.password ?? "";
  loginUri.value = item?.uri ?? editableCurrentUrl();
  loginNotes.value = item?.notes ?? "";
  loginFavorite.checked = item?.favorite ?? false;
  showView("editor");
  loginName.focus();
}

async function saveEditor(): Promise<void> {
  setBusy(editorSubmit, true, "Saving…");
  clearStatus();
  try {
    const login = {
      name: loginName.value,
      username: loginUsername.value,
      password: loginPassword.value,
      uri: loginUri.value,
      notes: loginNotes.value,
      favorite: loginFavorite.checked,
    };
    const id = editingId;
    const data = await request(id ? { type: "vault.update", id, login } : { type: "vault.create", login });
    if (data.type !== "done") throw new Error("The background worker returned an invalid save response.");
    editorForm.reset();
    editingId = null;
    selectedItem = null;
    showView("vault");
    await loadItems();
    showStatus(id ? "Login updated." : "Login added.", "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(editorSubmit, false, "Save login");
  }
}

function editableCurrentUrl(): string {
  if (!currentUrl) return "";
  try {
    const url = new URL(currentUrl);
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : "";
  } catch {
    return "";
  }
}

function suggestedSiteName(): string {
  const value = editableCurrentUrl();
  return value ? new URL(value).hostname.replace(/^www\./, "") : "";
}

function defaultGeneratedPassword(): string {
  return generatePassword({
    length: 22,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });
}

function refreshGeneratedPassword(): void {
  generatorLengthValue.value = generatorLength.value;
  try {
    generatorOutput.value = generatePassword({
      length: Number(generatorLength.value),
      uppercase: generatorUppercase.checked,
      lowercase: generatorLowercase.checked,
      numbers: generatorNumbers.checked,
      symbols: generatorSymbols.checked,
    });
    clearStatus();
  } catch (error) {
    generatorOutput.value = "";
    showError(error);
  }
}

async function authorizeReprompt(): Promise<void> {
  if (!selectedItem) {
    return;
  }
  setBusy(repromptSubmit, true, "Checking…");
  clearStatus();
  try {
    const id = selectedItem.id;
    const data = await request({
      type: "vault.authorize",
      id,
      masterPassword: repromptPassword.value,
    });
    if (data.type !== "done") {
      throw new Error("The background worker returned an invalid authorization response.");
    }
    repromptPassword.value = "";
    await showDetail(id);
    showStatus("Protected fields unlocked for 60 seconds.", "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(repromptSubmit, false, "Unlock protected fields");
  }
}

async function refreshTotp(): Promise<void> {
  if (!selectedItem?.hasTotp) {
    return;
  }
  try {
    const data = await request({ type: "vault.totp", id: selectedItem.id });
    if (data.type !== "totp") {
      throw new Error("The background worker returned an invalid authenticator code.");
    }
    detailTotp.textContent = `${data.code} · ${data.remaining}s`;
  } catch (error) {
    detailTotp.textContent = "Unavailable";
    showError(error);
  }
}

async function copyTotp(): Promise<void> {
  if (!selectedItem?.hasTotp) {
    return;
  }
  try {
    const data = await request({ type: "vault.totp", id: selectedItem.id });
    if (data.type !== "totp") {
      throw new Error("The background worker returned an invalid authenticator code.");
    }
    await copySecret(data.code, "Authenticator code copied.");
    detailTotp.textContent = `${data.code} · ${data.remaining}s`;
  } catch (error) {
    showError(error);
  }
}

async function fill(id: string): Promise<void> {
  try {
    const data = await request({ type: "vault.fill", id });
    if (data.type !== "fill") {
      throw new Error("The background worker returned an invalid fill response.");
    }
    showStatus(
      `Filled ${[data.username && "username", data.password && "password"].filter(Boolean).join(" and ")}.`,
      "success",
    );
  } catch (error) {
    showError(error);
  }
}

async function syncVault(): Promise<void> {
  clearStatus();
  try {
    const data = await request({ type: "vault.sync" });
    if (data.type !== "sync") {
      throw new Error("The background worker returned an invalid sync response.");
    }
    await refreshState();
    showStatus(`Synced ${data.itemCount} logins.`, "success");
  } catch (error) {
    showError(error);
  }
}

async function lock(): Promise<void> {
  try {
    await request({ type: "auth.lock" });
    selectedItem = null;
    await refreshState();
  } catch (error) {
    showError(error);
  }
}

async function logout(): Promise<void> {
  try {
    await request({ type: "auth.logout" });
    selectedItem = null;
    masterPassword.value = "";
    unlockPassword.value = "";
    await refreshState();
  } catch (error) {
    showError(error);
  }
}

function populateTwoFactor(providers: number[]): void {
  twoFactorProvider.replaceChildren();
  for (const provider of providers.filter((value) => [0, 1, 3, 8].includes(value))) {
    const option = document.createElement("option");
    option.value = String(provider);
    option.textContent = providerName(provider);
    twoFactorProvider.append(option);
  }
  if (twoFactorProvider.options.length === 0) {
    throw new Error("This account requires a two-step login method not supported by this build.");
  }
  updateTwoFactorControls();
}

function updateTwoFactorControls(): void {
  sendEmailCode.hidden = twoFactorProvider.value !== "1";
}

async function requestEmailCode(): Promise<void> {
  setBusy(sendEmailCode, true, "Sending…");
  try {
    const data = await request({
      type: "auth.sendEmailCode",
      baseUrl: normalizeServerEnvironment(serverUrl.value).baseUrl,
      email: email.value,
      masterPassword: masterPassword.value,
    });
    if (data.type !== "done") {
      throw new Error("The background worker returned an invalid email-code response.");
    }
    showStatus("Verification code sent by email.", "success");
    twoFactorToken.focus();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(sendEmailCode, false, "Send email code");
  }
}

function providerName(provider: number): string {
  return ({ 0: "Authenticator app", 1: "Email", 3: "YubiKey", 8: "Recovery code" } as Record<number, string>)[provider] ?? `Method ${provider}`;
}

async function copySecret(value: string, message: string): Promise<void> {
  try {
    if (!value) {
      throw new Error("This field is empty.");
    }
    await navigator.clipboard.writeText(value);
    showStatus(message, "success");
  } catch (error) {
    showError(error);
  }
}

async function activeTabUrl(): Promise<string | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url;
  } catch {
    return undefined;
  }
}

async function request(value: ExtensionRequest): Promise<ResponseData> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) {
    throw new Error("The extension background worker did not respond. Reload the extension.");
  }
  if (!response.ok) {
    throw new Error(response.error);
  }
  return response.data;
}

function showView(name: keyof typeof views): void {
  for (const [key, view] of Object.entries(views)) {
    view.hidden = key !== name;
  }
  const unlockedView = ["vault", "generator", "settings", "detail", "editor"].includes(name);
  const mainTab = name === "vault" || name === "generator" || name === "settings";
  document.body.classList.toggle("nav-hidden", !mainTab);
  bottomNav.hidden = !mainTab;
  addLogin.hidden = !mainTab;
  accountAvatar.hidden = !unlockedView;
  statePill.hidden = unlockedView;
  brandMark.hidden = unlockedView;
  subtitle.hidden = unlockedView;
  navVault.classList.toggle("active", name === "vault");
  navGenerator.classList.toggle("active", name === "generator");
  accountAvatar.classList.toggle("active", name === "settings");
  appTitle.textContent = ({
    setup: "LeanVault",
    login: "LeanVault",
    locked: "LeanVault",
    vault: "Vault",
    generator: "Generator",
    settings: "Settings",
    detail: "Login",
    editor: editingId ? "Edit login" : "New login",
  } satisfies Record<keyof typeof views, string>)[name];
}

function markState(text: string, style: "neutral" | "success" | "error"): void {
  statePill.textContent = text;
  statePill.className = `pill ${style}`;
}

function serverLabel(baseUrl: string, version?: string): string {
  return version ? `${baseUrl} · server ${version}` : baseUrl;
}

function accountInitials(accountEmail: string): string {
  const local = accountEmail.split("@", 1)[0]?.replace(/[^a-z]/gi, "") ?? "";
  return (local.slice(0, 2) || "LV").toLocaleUpperCase();
}

function setBusy(button: HTMLButtonElement, busy: boolean, label: string): void {
  button.disabled = busy;
  button.textContent = label;
}

function clearStatus(): void {
  status.textContent = "";
  status.className = "status";
}

function showStatus(message: string, style: "neutral" | "success" | "error"): void {
  status.textContent = message;
  status.className = `status ${style === "success" ? "success-text" : style === "error" ? "error-text" : ""}`;
}

function showError(error: unknown): void {
  showStatus(error instanceof Error ? error.message : "Unexpected extension error.", "error");
}

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) {
    throw new Error(`Missing popup element #${id}`);
  }
  return value as T;
}
