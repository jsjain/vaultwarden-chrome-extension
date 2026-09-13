import type { ExtensionRequest, ExtensionResponse, ResponseData } from "../shared/messages";
import type { LoginWriteInput } from "../vault/encrypt-login";
import { canBeUsernameField, looksLikeUsernameField } from "./field-detection";

type Suggestion = Extract<ResponseData, { type: "siteSuggestions" }>["items"][number];
type SitePrompt = NonNullable<Extract<ResponseData, { type: "sitePrompt" }>["prompt"]>;

const marker = "data-leanvault-loaded";
let suggestions: Suggestion[] = [];
let suggestionsUrl = "";
let suggestionsLoad: Promise<void> | null = null;
let lastUsername = "";
let lastCapture = "";
let activeField: HTMLInputElement | null = null;
let activeFieldKind: "username" | "password" | null = null;
let activeSavePromptId: string | null = null;
let dismissActiveSavePrompt: (() => void) | null = null;

if (!document.documentElement.hasAttribute(marker)) {
  document.documentElement.setAttribute(marker, "true");
  void initialize();
}

async function initialize(): Promise<void> {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.accountMetadata) suggestionsUrl = "";
  });
  document.addEventListener("focusin", handleFocus, true);
  document.addEventListener("input", rememberInput, true);
  document.addEventListener("submit", captureLogin, true);
  document.addEventListener("pointerdown", captureSubmitPointer, true);
  document.addEventListener("pointerdown", dismissFieldMenuOnOutsideClick, true);
  document.addEventListener("keydown", captureEnter, true);
  document.addEventListener("keydown", dismissOverlaysOnEscape, true);
  window.addEventListener("scroll", repositionOpenOverlay, true);
  window.addEventListener("resize", repositionOpenOverlay);
  observeDynamicCredentialFields();
  const [, pending] = await Promise.allSettled([
    loadSuggestions(),
    request({ type: "site.pendingPrompt" }),
  ]);
  if (pending.status === "fulfilled" && pending.value.type === "sitePrompt" && pending.value.prompt) {
    renderSavePrompt(pending.value.prompt);
  }
  const focused = deepActiveInput();
  if (focused && isCredentialField(focused)) activateField(focused);
}

function handleFocus(event: FocusEvent): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (!(input instanceof HTMLInputElement) || !isCredentialField(input)) return;
  activateField(input);
}

function activateField(input: HTMLInputElement): void {
  activeField = input;
  activeFieldKind = input.type.toLowerCase() === "password" ? "password" : "username";
  if (isUsernameField(input) && input.value) lastUsername = input.value;
  void loadSuggestions().then(() => {
    if (activeField !== input || !input.isConnected || !isCredentialField(input)) return;
    if (isUsernameField(input)) showFieldToggle(input);
    else document.getElementById("leanvault-field-toggle")?.remove();
    showFieldMenu(input);
  });
}

async function loadSuggestions(): Promise<void> {
  const url = location.href;
  if (suggestionsUrl === url) return;
  if (suggestionsLoad) return suggestionsLoad.then(loadSuggestions);
  suggestionsLoad = request({ type: "site.suggestions", url }).then((matches) => {
    if (location.href !== url) return;
    suggestions = matches.type === "siteSuggestions" ? matches.items : [];
    suggestionsUrl = url;
  }).catch(() => {
    if (location.href === url) {
      suggestions = [];
      suggestionsUrl = url;
    }
  }).finally(() => { suggestionsLoad = null; });
  return suggestionsLoad;
}

function observeDynamicCredentialFields(): void {
  let scheduled = false;
  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const focused = deepActiveInput();
      const focusedKind = focused?.type.toLowerCase() === "password" ? "password" : "username";
      if (focused && isCredentialField(focused) && (focused !== activeField || focusedKind !== activeFieldKind)) {
        activateField(focused);
      } else if (activeField && (!activeField.isConnected || !isCredentialField(activeField))) {
        activeField = null;
        activeFieldKind = null;
        document.getElementById("leanvault-field-toggle")?.remove();
        closeFieldMenu();
      }
    });
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["type", "name", "id", "autocomplete", "placeholder", "aria-label", "aria-labelledby"],
  });
}

function rememberInput(event: Event): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (input instanceof HTMLInputElement && isUsernameField(input) && input.value) lastUsername = input.value;
}

function showFieldMenu(input: HTMLInputElement): void {
  closeFieldMenu();
  if (suggestions.length === 0 && input.type.toLowerCase() !== "password") return;
  const host = overlayHost("leanvault-field-menu", input);
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><div class="field-menu" role="listbox"><div class="menu-title"><span>LeanVault</span><button class="menu-close" type="button" aria-label="Dismiss autofill suggestions" title="Dismiss">×</button></div><div class="choices"></div></div>`;
  const choices = root.querySelector<HTMLDivElement>(".choices")!;
  const close = root.querySelector<HTMLButtonElement>(".menu-close")!;
  close.addEventListener("pointerdown", (event) => event.preventDefault());
  close.addEventListener("click", () => closeFieldMenu(host));
  for (const item of suggestions) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "choice";
    const icon = document.createElement("span");
    icon.className = "site-icon";
    icon.textContent = item.name.charAt(0).toUpperCase() || "L";
    const image = document.createElement("img");
    image.src = faviconUrl(item.uri);
    image.alt = "";
    image.addEventListener("load", () => { icon.textContent = ""; icon.append(image); });
    const copy = document.createElement("span");
    copy.className = "choice-copy";
    const name = document.createElement("strong");
    name.textContent = item.name;
    const username = document.createElement("span");
    username.textContent = item.username || "Login";
    copy.append(name, username);
    const glyph = document.createElement("span");
    glyph.className = "fill-glyph";
    glyph.textContent = "↗";
    button.append(icon, copy, glyph);
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", () => void fill(item.id, input));
    choices.append(button);
  }
  if (input.type.toLowerCase() === "password") {
    const generate = document.createElement("button");
    generate.type = "button";
    generate.className = "generate-choice";
    generate.textContent = "⚙  Generate and fill a password";
    generate.addEventListener("pointerdown", (event) => event.preventDefault());
    generate.addEventListener("click", () => void generateAndFill(input, host));
    choices.append(generate);
  }
  setFieldToggleExpanded(true);
  positionHost(host, input);
}

function showFieldToggle(input: HTMLInputElement): void {
  document.getElementById("leanvault-field-toggle")?.remove();
  if (!isUsernameField(input) || suggestions.length === 0) return;
  const host = overlayHost("leanvault-field-toggle", input);
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><button class="field-toggle" type="button" aria-label="Toggle LeanVault suggestions" aria-expanded="true" title="Show or hide LeanVault suggestions"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="3" width="16" height="18" rx="3"/><path d="M3 7h3M3 17h3"/><circle cx="13" cy="12" r="5"/><circle cx="13" cy="12" r="1.7"/><path d="M13 7v1.5M13 15.5V17M8 12h1.5M16.5 12H18"/></svg></button>`;
  const button = root.querySelector<HTMLButtonElement>(".field-toggle")!;
  button.addEventListener("pointerdown", (event) => event.preventDefault());
  button.addEventListener("click", () => {
    const menu = document.getElementById("leanvault-field-menu");
    if (menu) closeFieldMenu(menu);
    else showFieldMenu(input);
  });
  positionFieldToggle(host, input);
}

function closeFieldMenu(host = document.getElementById("leanvault-field-menu")): void {
  host?.remove();
  setFieldToggleExpanded(false);
}

function setFieldToggleExpanded(expanded: boolean): void {
  const button = document.getElementById("leanvault-field-toggle")?.shadowRoot?.querySelector<HTMLButtonElement>(".field-toggle");
  button?.setAttribute("aria-expanded", String(expanded));
  button?.classList.toggle("expanded", expanded);
}

function dismissFieldMenuOnOutsideClick(event: PointerEvent): void {
  const host = document.getElementById("leanvault-field-menu");
  if (!host) return;
  const path = event.composedPath();
  const toggle = document.getElementById("leanvault-field-toggle");
  if (path.includes(host) || (toggle && path.includes(toggle)) || (activeField && path.includes(activeField))) return;
  closeFieldMenu(host);
}

function dismissOverlaysOnEscape(event: KeyboardEvent): void {
  if (event.key !== "Escape") return;
  const menu = document.getElementById("leanvault-field-menu");
  if (menu) {
    closeFieldMenu(menu);
    event.stopPropagation();
  }
  if (dismissActiveSavePrompt) {
    dismissActiveSavePrompt();
    event.stopPropagation();
  }
}

async function fill(id: string, preferred: HTMLInputElement): Promise<void> {
  try {
    const data = await request({ type: "site.credential", id, url: location.href });
    if (data.type !== "siteCredential") return;
    const password = preferred.type.toLowerCase() === "password" ? preferred : findPasswordField(preferred);
    const username = findUsernameField(password, preferred);
    setInputValue(username, data.username);
    setInputValue(password, data.password);
    closeFieldMenu();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "LeanVault could not fill this login.");
  }
}

async function generateAndFill(input: HTMLInputElement, host: HTMLElement): Promise<void> {
  try {
    const data = await request({ type: "site.generatePassword", url: location.href });
    if (data.type !== "generatedPassword") return;
    setInputValue(input, data.password);
    input.focus();
    input.select();
    closeFieldMenu(host);
    showTransient("A generated password was filled. Save it after submitting this form.");
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "LeanVault could not generate a password.");
  }
}

function captureLogin(event: Event): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  inspectCredentials(event.target instanceof HTMLFormElement ? event.target : document);
}

function captureSubmitPointer(event: PointerEvent): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  const target = event.composedPath().find((value) => value instanceof Element);
  if (!(target instanceof Element)) return;
  const control = target.closest<HTMLElement>('button,input[type="submit"],[role="button"]');
  if (!control || !looksLikeSubmit(control)) return;
  inspectCredentials(control instanceof HTMLButtonElement || control instanceof HTMLInputElement ? control.form ?? document : document);
}

function captureEnter(event: KeyboardEvent): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  if (event.key !== "Enter") return;
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (input instanceof HTMLInputElement) inspectCredentials(input.form ?? document);
}

function looksLikeSubmit(control: HTMLElement): boolean {
  if (control instanceof HTMLInputElement) return control.type.toLowerCase() === "submit";
  if (control instanceof HTMLButtonElement && (control.type === "submit" || Boolean(control.form))) return true;
  const label = `${control.textContent ?? ""} ${control.getAttribute("aria-label") ?? ""}`.toLowerCase();
  return /sign\s*in|log\s*in|login|continue|submit|next|verify/.test(label);
}

function inspectCredentials(scope: ParentNode): void {
  const passwordField = credentialInputs(scope).filter((input) => isPasswordField(input) && input.value).at(-1) ??
    findPasswordField();
  if (!passwordField?.value) return;
  const username = findUsernameField(passwordField)?.value || lastUsername;
  const fingerprint = `${location.origin}\0${username}\0${passwordField.value}`;
  if (fingerprint === lastCapture) return;
  lastCapture = fingerprint;
  setTimeout(() => { lastCapture = ""; }, 3_000);
  void request({
    type: "site.inspect",
    url: location.href,
    username,
    password: passwordField.value,
  }).then((data) => {
    if (data.type === "sitePrompt" && data.prompt) renderSavePrompt(data.prompt);
  }).catch(() => undefined);
}

function renderSavePrompt(prompt: SitePrompt): void {
  if (activeSavePromptId === prompt.id || prompt.expiresAt <= Date.now()) return;
  dismissActiveSavePrompt?.();
  activeSavePromptId = prompt.id;
  const host = overlayHost("leanvault-save-prompt");
  host.style.top = "18px";
  host.style.right = "18px";
  host.style.bottom = "auto";
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><form class="prompt">
    <div class="prompt-heading"><strong>${prompt.action === "update" ? "Update existing login" : "Save login to LeanVault"}</strong><button class="close" type="button" aria-label="Not now">×</button></div>
    <label>Name<input class="prompt-name" maxlength="1000" required></label>
    <label>Username<input class="prompt-username" maxlength="1000"></label>
    <label>Password<div class="password-edit"><input class="prompt-password" type="password" maxlength="10000"><button class="show" type="button">Show</button></div></label>
    <label>Website<input class="prompt-uri" type="url" maxlength="8192"></label>
    <div class="prompt-actions"><button class="dismiss" type="button">Not now</button><button class="save" type="submit">${prompt.action === "update" ? "Update" : "Save"}</button></div>
  </form>`;
  const form = root.querySelector<HTMLFormElement>("form")!;
  const name = root.querySelector<HTMLInputElement>(".prompt-name")!;
  const username = root.querySelector<HTMLInputElement>(".prompt-username")!;
  const password = root.querySelector<HTMLInputElement>(".prompt-password")!;
  const uri = root.querySelector<HTMLInputElement>(".prompt-uri")!;
  name.value = prompt.name;
  username.value = prompt.username ?? "";
  password.value = prompt.password ?? "";
  uri.value = prompt.uri ?? location.href;
  root.querySelector<HTMLButtonElement>(".show")!.addEventListener("click", (event) => {
    const button = event.currentTarget as HTMLButtonElement;
    password.type = password.type === "password" ? "text" : "password";
    button.textContent = password.type === "password" ? "Show" : "Hide";
  });
  let dismissed = false;
  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    clearTimeout(dismissTimer);
    activeSavePromptId = null;
    dismissActiveSavePrompt = null;
    void request({ type: "site.dismiss", promptId: prompt.id }).catch(() => undefined);
    host.remove();
  };
  let dismissTimer = setTimeout(dismiss, Math.max(0, prompt.expiresAt - Date.now()));
  dismissActiveSavePrompt = dismiss;
  for (const button of root.querySelectorAll<HTMLButtonElement>(".dismiss,.close")) {
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", dismiss);
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const save = root.querySelector<HTMLButtonElement>(".save")!;
    save.disabled = true;
    clearTimeout(dismissTimer);
    save.textContent = "Saving…";
    const login: LoginWriteInput = { name: name.value, username: username.value, password: password.value, uri: uri.value };
    void request({ type: "site.save", promptId: prompt.id, login }).then(() => {
      dismissed = true;
      activeSavePromptId = null;
      dismissActiveSavePrompt = null;
      host.remove();
      showTransient(prompt.action === "update" ? "Login updated." : "Login saved.");
    }).catch((error: unknown) => {
      dismissTimer = setTimeout(dismiss, Math.max(0, prompt.expiresAt - Date.now()));
      save.disabled = false;
      save.textContent = prompt.action === "update" ? "Update" : "Save";
      showTransient(error instanceof Error ? error.message : "LeanVault could not save this login.");
    });
  });
}

function overlayHost(id: string, anchor?: HTMLInputElement): HTMLDivElement {
  document.getElementById(id)?.remove();
  const host = document.createElement("div");
  host.id = id;
  host.style.cssText = "all:initial;display:block;position:fixed;inset:auto 18px 18px auto;margin:0;padding:0;border:0;background:transparent;overflow:visible;pointer-events:auto;z-index:2147483647;width:min(390px,calc(100vw - 24px))";
  if (anchor) host.dataset.anchor = "true";
  host.setAttribute("popover", "manual");
  host.attachShadow({ mode: "open" });
  document.documentElement.append(host);
  showInTopLayer(host);
  return host;
}

function showInTopLayer(host: HTMLElement): void {
  try {
    host.showPopover();
  } catch {
    // Chrome versions without Popover API keep the maximum-z-index fallback.
  }
  requestAnimationFrame(() => {
    if (!host.isConnected) return;
    try {
      if (host.matches(":popover-open")) host.hidePopover();
      host.showPopover();
    } catch {
      document.documentElement.append(host);
    }
  });
}

function positionHost(host: HTMLElement, anchor: HTMLInputElement): void {
  if (!anchor.isConnected) return;
  const rect = anchor.getBoundingClientRect();
  const width = Math.max(280, Math.min(390, rect.width));
  const left = Math.max(8, Math.min(innerWidth - width - 8, rect.left));
  const estimatedHeight = host.id === "leanvault-save-prompt" ? 390 : Math.min(360, 54 + suggestions.length * 66 + 44);
  const below = innerHeight - rect.bottom >= Math.min(estimatedHeight, 240);
  host.style.width = `${width}px`;
  host.style.right = "auto";
  host.style.bottom = "auto";
  host.style.left = `${left}px`;
  host.style.top = `${Math.max(8, below ? rect.bottom + 4 : rect.top - Math.min(estimatedHeight, rect.top - 8) - 4)}px`;
}

function positionFieldToggle(host: HTMLElement, input: HTMLInputElement): void {
  if (!input.isConnected || !visible(input)) {
    host.remove();
    closeFieldMenu();
    return;
  }
  const rect = input.getBoundingClientRect();
  const size = Math.max(24, Math.min(34, rect.height - 8));
  host.style.width = `${size}px`;
  host.style.height = `${size}px`;
  host.style.right = "auto";
  host.style.bottom = "auto";
  host.style.left = `${Math.max(2, rect.right - size - 7)}px`;
  host.style.top = `${rect.top + Math.max(4, (rect.height - size) / 2)}px`;
}

function repositionOpenOverlay(): void {
  if (!activeField) return;
  const menu = document.getElementById("leanvault-field-menu");
  if (menu) positionHost(menu, activeField);
  const toggle = document.getElementById("leanvault-field-toggle");
  if (toggle) positionFieldToggle(toggle, activeField);
}

function showTransient(message: string): void {
  const host = overlayHost("leanvault-toast");
  host.shadowRoot!.innerHTML = `<style>${styles}</style><div class="toast"></div>`;
  host.shadowRoot!.querySelector<HTMLDivElement>(".toast")!.textContent = message;
  setTimeout(() => host.remove(), 3_500);
}

function isExtensionElement(element: Element): boolean {
  if (element.id.startsWith("leanvault-")) return true;
  const root = element.getRootNode();
  return root instanceof ShadowRoot && isExtensionElement(root.host);
}

function allRoots(): ParentNode[] {
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot && !isExtensionElement(element)) roots.push(element.shadowRoot);
    }
  }
  return roots;
}

function credentialInputs(scope?: ParentNode): HTMLInputElement[] {
  const roots = scope && scope !== document ? [scope] : allRoots();
  return roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(visible);
}

function findPasswordField(preferred?: HTMLInputElement): HTMLInputElement | undefined {
  if (preferred && isPasswordField(preferred) && visible(preferred)) return preferred;
  const passwords = credentialInputs().filter(isPasswordField);
  return passwords.find((input) => input.autocomplete.toLowerCase() === "current-password") ??
    passwords.find((input) => input.autocomplete.toLowerCase() !== "new-password") ?? passwords[0];
}

function findUsernameField(password?: HTMLInputElement, preferred?: HTMLInputElement): HTMLInputElement | undefined {
  if (preferred && preferred !== password && isUsernameField(preferred) && visible(preferred)) return preferred;
  const candidates = credentialInputs().filter((input) => input !== password && isUsernameField(input));
  const score = (input: HTMLInputElement): number => {
    const hint = inputHint(input);
    let value = 0;
    if (/username|user-name|login|email|e-mail/.test(hint)) value += 12;
    if (["username", "email"].includes(input.autocomplete.toLowerCase())) value += 15;
    if (input.type.toLowerCase() === "email") value += 10;
    if (/search|otp|code|phone|mobile|captcha/.test(hint)) value -= 20;
    if (password && input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) value += 3;
    return value;
  };
  return candidates.sort((left, right) => score(right) - score(left))[0];
}

function isPasswordField(input: HTMLInputElement): boolean {
  return input.type.toLowerCase() === "password" &&
    !/one-time-code|\botp\b|verification.?code|security.?code|authenticator.?code/.test(inputHint(input));
}

function isCredentialField(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  return isPasswordField(input) || isUsernameField(input);
}

function isUsernameField(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  const type = input.type.toLowerCase();
  const hint = inputHint(input);
  const root = input.getRootNode();
  const scope = input.form ?? (root instanceof Document || root instanceof ShadowRoot ? root : document);
  const eligibleFieldCount = credentialInputs(scope).filter((candidate) =>
    canBeUsernameField(candidate.type, inputHint(candidate)),
  ).length;
  return looksLikeUsernameField({
    type,
    autocomplete: input.autocomplete,
    inputHint: hint,
    contextHint: credentialContextHint(input),
    eligibleFieldCount,
  });
}

function inputHint(input: HTMLInputElement): string {
  const root = input.getRootNode();
  const labelledBy = (input.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter(Boolean)
    .map((id) => root instanceof Document || root instanceof ShadowRoot ? root.getElementById(id)?.textContent ?? "" : "")
    .join(" ");
  const labels = [...(input.labels ?? [])].map((label) => label.textContent ?? "").join(" ");
  return `${input.autocomplete} ${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""} ${labelledBy} ${labels}`.toLowerCase();
}

function credentialContextHint(input: HTMLInputElement): string {
  const form = input.form;
  const controls = form ? [...form.querySelectorAll<HTMLElement>('button,input[type="submit"],[role="button"]')]
    .map((control) => `${control.textContent ?? ""} ${control.getAttribute("aria-label") ?? ""}`)
    .join(" ") : "";
  return `${document.title} ${location.pathname} ${form?.id ?? ""} ${form?.getAttribute("name") ?? ""} ${form?.getAttribute("action") ?? ""} ${form?.getAttribute("aria-label") ?? ""} ${controls}`;
}

function visible(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  if (input.disabled || input.readOnly || input.type.toLowerCase() === "hidden") return false;
  const bounds = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return bounds.width > 1 && bounds.height > 1 && input.getClientRects().length > 0 &&
    style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity || "1") > 0;
}

function setInputValue(input: HTMLInputElement | undefined, value: string): boolean {
  if (!input || !value) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
  try {
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
  } catch {
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

function deepActiveInput(): HTMLInputElement | null {
  let active: Element | null = document.activeElement;
  while (active instanceof HTMLElement && active.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active instanceof HTMLInputElement ? active : null;
}

function faviconUrl(uri?: string): string {
  try {
    return `${new URL(uri ?? location.href).origin}/favicon.ico`;
  } catch {
    return `${location.origin}/favicon.ico`;
  }
}

async function request(value: ExtensionRequest): Promise<ResponseData> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) throw new Error("LeanVault is unavailable.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

const styles = `
  *{box-sizing:border-box;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
  button,input{font:inherit}button{cursor:pointer}.field-menu,.prompt{overflow:hidden;border:1px solid #525a67;border-radius:10px;background:#2e333c;color:#f6f7f9;box-shadow:0 10px 30px #0005}
  .menu-title{display:flex;min-height:38px;align-items:center;justify-content:space-between;gap:8px;padding:5px 7px 5px 12px;border-bottom:1px solid #474e59;color:#aeb5c0;font-size:11px;font-weight:750}.menu-close{display:grid;width:28px;height:28px;padding:0;place-items:center;border:0;border-radius:7px;background:transparent;color:#c8cdd5;font-size:20px;line-height:1}.menu-close:hover,.menu-close:focus-visible{background:#414751;color:#fff;outline:none}
  .field-toggle{display:grid;width:100%;height:100%;padding:4px;place-items:center;border:1px solid #69727f;border-radius:8px;background:#4b525e;color:#f3f4f6;box-shadow:0 2px 8px #0004}.field-toggle:hover,.field-toggle:focus-visible,.field-toggle.expanded{background:#626b78;outline:none}.field-toggle svg{width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
  .choices{max-height:310px;overflow:auto}.choice,.generate-choice{display:flex;width:100%;align-items:center;gap:11px;padding:10px 12px;border:0;border-bottom:1px solid #454b55;background:#2e333c;color:#f6f7f9;text-align:left}
  .choice:hover,.generate-choice:hover{background:#3a404a}.site-icon{display:grid;width:34px;height:34px;flex:none;overflow:hidden;place-items:center;border-radius:7px;background:#202630;color:#d7dce3;font-weight:800}.site-icon img{width:24px;height:24px;object-fit:contain}
  .choice-copy{display:grid;min-width:0;flex:1;gap:2px}.choice-copy strong,.choice-copy span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.choice-copy strong{font-size:13px}.choice-copy span{color:#c1c6cf;font-size:11px}.fill-glyph{color:#b8bec8;font-size:22px}.generate-choice{justify-content:center;border-bottom:0;color:#e3e6eb;font-size:12px;font-weight:750}
  .prompt{max-height:calc(100vh - 16px);overflow:auto;padding:14px}.prompt-heading{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}.prompt-heading strong{font-size:14px}.close{width:28px;height:28px;border:0;border-radius:7px;background:transparent;color:#bec4cc;font-size:20px}.close:hover{background:#414751}
  .prompt label{display:grid;gap:4px;margin-top:8px;color:#c7ccd4;font-size:10px;font-weight:750}.prompt input{width:100%;height:34px;padding:6px 9px;border:1px solid #555d69;border-radius:7px;background:#20252d;color:#f7f8fa;outline:none}.prompt input:focus{border-color:#9aa2ae}.password-edit{display:flex;gap:6px}.password-edit input{flex:1}.show{min-width:54px;border:1px solid #555d69;border-radius:7px;background:#3d444f;color:#fff;font-size:10px;font-weight:700}
  .prompt-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:13px}.prompt-actions button{height:34px;padding:0 13px;border:1px solid #59616d;border-radius:8px;font-size:11px;font-weight:750}.save{background:#a5acb7;color:#15181d}.dismiss{background:#343a44;color:#f3f4f6}
  .toast{max-width:390px;padding:11px 14px;border:1px solid #555d69;border-radius:9px;background:#292e36;color:#fff;box-shadow:0 7px 24px #0005;font:12px Inter,system-ui,sans-serif}
`;
