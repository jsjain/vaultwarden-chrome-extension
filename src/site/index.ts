import type { ExtensionRequest, ExtensionResponse, ResponseData } from "../shared/messages";
import type { LoginWriteInput } from "../vault/encrypt-login";

type Suggestion = Extract<ResponseData, { type: "siteSuggestions" }>["items"][number];
type SitePrompt = NonNullable<Extract<ResponseData, { type: "sitePrompt" }>["prompt"]>;

const marker = "data-leanvault-loaded";
let suggestions: Suggestion[] = [];
let lastUsername = "";
let lastCapture = "";
let activeField: HTMLInputElement | null = null;

if (!document.documentElement.hasAttribute(marker)) {
  document.documentElement.setAttribute(marker, "true");
  void initialize();
}

async function initialize(): Promise<void> {
  document.addEventListener("focusin", handleFocus, true);
  document.addEventListener("input", rememberInput, true);
  document.addEventListener("submit", captureLogin, true);
  document.addEventListener("pointerdown", captureSubmitPointer, true);
  document.addEventListener("keydown", captureEnter, true);
  window.addEventListener("scroll", repositionOpenOverlay, true);
  window.addEventListener("resize", repositionOpenOverlay);
  try {
    const [matches, pending] = await Promise.all([
      request({ type: "site.suggestions", url: location.href }),
      request({ type: "site.pendingPrompt" }),
    ]);
    if (matches.type === "siteSuggestions") suggestions = matches.items;
    if (pending.type === "sitePrompt" && pending.prompt) renderSavePrompt(pending.prompt);
    const focused = deepActiveInput();
    if (focused && isCredentialField(focused)) showFieldMenu(focused);
  } catch {
    // Locked, excluded, and signed-out vaults stay silent on the page.
  }
}

function handleFocus(event: FocusEvent): void {
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (!(input instanceof HTMLInputElement) || !isCredentialField(input)) return;
  activeField = input;
  if (isUsernameField(input) && input.value) lastUsername = input.value;
  showFieldMenu(input);
}

function rememberInput(event: Event): void {
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (input instanceof HTMLInputElement && isUsernameField(input) && input.value) lastUsername = input.value;
}

function showFieldMenu(input: HTMLInputElement): void {
  document.getElementById("leanvault-field-menu")?.remove();
  if (suggestions.length === 0 && input.type.toLowerCase() !== "password") return;
  const host = overlayHost("leanvault-field-menu", input);
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><div class="field-menu" role="listbox"><div class="menu-title">LeanVault</div><div class="choices"></div></div>`;
  const choices = root.querySelector<HTMLDivElement>(".choices")!;
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
    button.addEventListener("click", () => void fill(item.id, input, host));
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
  requestAnimationFrame(() => positionHost(host, input));
}

async function fill(id: string, preferred: HTMLInputElement, host: HTMLElement): Promise<void> {
  try {
    const data = await request({ type: "site.credential", id, url: location.href });
    if (data.type !== "siteCredential") return;
    const password = preferred.type.toLowerCase() === "password" ? preferred : findPasswordField(preferred);
    const username = findUsernameField(password, preferred);
    setInputValue(username, data.username);
    setInputValue(password, data.password);
    (password ?? username)?.focus();
    host.remove();
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
    host.remove();
    showTransient("A generated password was filled. Save it after submitting this form.");
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "LeanVault could not generate a password.");
  }
}

function captureLogin(event: Event): void {
  inspectCredentials(event.target instanceof HTMLFormElement ? event.target : document);
}

function captureSubmitPointer(event: PointerEvent): void {
  const target = event.composedPath().find((value) => value instanceof Element);
  if (!(target instanceof Element)) return;
  const control = target.closest<HTMLElement>('button,input[type="submit"],[role="button"]');
  if (!control || !looksLikeSubmit(control)) return;
  inspectCredentials(control instanceof HTMLButtonElement || control instanceof HTMLInputElement ? control.form ?? document : document);
}

function captureEnter(event: KeyboardEvent): void {
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
  const passwordField = credentialInputs(scope).filter((input) => input.type.toLowerCase() === "password" && input.value).at(-1) ??
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
    if (data.type === "sitePrompt" && data.prompt) renderSavePrompt(data.prompt, passwordField);
  }).catch(() => undefined);
}

function renderSavePrompt(prompt: SitePrompt, anchor?: HTMLInputElement): void {
  document.getElementById("leanvault-save-prompt")?.remove();
  const host = overlayHost("leanvault-save-prompt", anchor);
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
  const dismiss = () => {
    void request({ type: "site.dismiss", promptId: prompt.id });
    host.remove();
  };
  root.querySelector<HTMLButtonElement>(".dismiss")!.addEventListener("click", dismiss);
  root.querySelector<HTMLButtonElement>(".close")!.addEventListener("click", dismiss);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const save = root.querySelector<HTMLButtonElement>(".save")!;
    save.disabled = true;
    save.textContent = "Saving…";
    const login: LoginWriteInput = { name: name.value, username: username.value, password: password.value, uri: uri.value };
    void request({ type: "site.save", promptId: prompt.id, login }).then(() => {
      host.remove();
      showTransient(prompt.action === "update" ? "Login updated." : "Login saved.");
    }).catch((error: unknown) => {
      save.disabled = false;
      save.textContent = prompt.action === "update" ? "Update" : "Save";
      showTransient(error instanceof Error ? error.message : "LeanVault could not save this login.");
    });
  });
  if (anchor) requestAnimationFrame(() => positionHost(host, anchor));
}

function overlayHost(id: string, anchor?: HTMLInputElement): HTMLDivElement {
  document.getElementById(id)?.remove();
  const host = document.createElement("div");
  host.id = id;
  host.style.cssText = "all:initial;position:fixed;right:18px;bottom:18px;z-index:2147483647;width:min(390px,calc(100vw - 24px))";
  if (anchor) host.dataset.anchor = "true";
  host.attachShadow({ mode: "open" });
  document.documentElement.append(host);
  return host;
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

function repositionOpenOverlay(): void {
  if (!activeField) return;
  const menu = document.getElementById("leanvault-field-menu");
  if (menu) positionHost(menu, activeField);
}

function showTransient(message: string): void {
  const host = overlayHost("leanvault-toast");
  host.shadowRoot!.innerHTML = `<style>${styles}</style><div class="toast"></div>`;
  host.shadowRoot!.querySelector<HTMLDivElement>(".toast")!.textContent = message;
  setTimeout(() => host.remove(), 3_500);
}

function allRoots(): ParentNode[] {
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  return roots;
}

function credentialInputs(scope?: ParentNode): HTMLInputElement[] {
  const roots = scope && scope !== document ? [scope] : allRoots();
  return roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(visible);
}

function findPasswordField(preferred?: HTMLInputElement): HTMLInputElement | undefined {
  if (preferred?.type.toLowerCase() === "password" && visible(preferred)) return preferred;
  const passwords = credentialInputs().filter((input) => input.type.toLowerCase() === "password");
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

function isCredentialField(input: HTMLInputElement): boolean {
  return input.type.toLowerCase() === "password" || isUsernameField(input);
}

function isUsernameField(input: HTMLInputElement): boolean {
  const type = input.type.toLowerCase();
  if (!["", "text", "email", "tel"].includes(type)) return false;
  const hint = inputHint(input);
  return !/search|otp|one-time|captcha/.test(hint) &&
    (type === "email" || /username|user-name|login|email|e-mail|phone|mobile/.test(hint));
}

function inputHint(input: HTMLInputElement): string {
  return `${input.autocomplete} ${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`.toLowerCase();
}

function visible(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || input.type.toLowerCase() === "hidden") return false;
  const bounds = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return bounds.width > 1 && bounds.height > 1 && input.getClientRects().length > 0 &&
    style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity || "1") > 0;
}

function setInputValue(input: HTMLInputElement | undefined, value: string): boolean {
  if (!input || !value) return false;
  input.focus();
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
  .menu-title{padding:7px 12px;border-bottom:1px solid #474e59;color:#aeb5c0;font-size:11px;font-weight:750}
  .choices{max-height:310px;overflow:auto}.choice,.generate-choice{display:flex;width:100%;align-items:center;gap:11px;padding:10px 12px;border:0;border-bottom:1px solid #454b55;background:#2e333c;color:#f6f7f9;text-align:left}
  .choice:hover,.generate-choice:hover{background:#3a404a}.site-icon{display:grid;width:34px;height:34px;flex:none;overflow:hidden;place-items:center;border-radius:7px;background:#202630;color:#d7dce3;font-weight:800}.site-icon img{width:24px;height:24px;object-fit:contain}
  .choice-copy{display:grid;min-width:0;flex:1;gap:2px}.choice-copy strong,.choice-copy span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.choice-copy strong{font-size:13px}.choice-copy span{color:#c1c6cf;font-size:11px}.fill-glyph{color:#b8bec8;font-size:22px}.generate-choice{justify-content:center;border-bottom:0;color:#e3e6eb;font-size:12px;font-weight:750}
  .prompt{max-height:calc(100vh - 16px);overflow:auto;padding:14px}.prompt-heading{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}.prompt-heading strong{font-size:14px}.close{width:28px;height:28px;border:0;border-radius:7px;background:transparent;color:#bec4cc;font-size:20px}.close:hover{background:#414751}
  .prompt label{display:grid;gap:4px;margin-top:8px;color:#c7ccd4;font-size:10px;font-weight:750}.prompt input{width:100%;height:34px;padding:6px 9px;border:1px solid #555d69;border-radius:7px;background:#20252d;color:#f7f8fa;outline:none}.prompt input:focus{border-color:#9aa2ae}.password-edit{display:flex;gap:6px}.password-edit input{flex:1}.show{min-width:54px;border:1px solid #555d69;border-radius:7px;background:#3d444f;color:#fff;font-size:10px;font-weight:700}
  .prompt-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:13px}.prompt-actions button{height:34px;padding:0 13px;border:1px solid #59616d;border-radius:8px;font-size:11px;font-weight:750}.save{background:#a5acb7;color:#15181d}.dismiss{background:#343a44;color:#f3f4f6}
  .toast{max-width:390px;padding:11px 14px;border:1px solid #555d69;border-radius:9px;background:#292e36;color:#fff;box-shadow:0 7px 24px #0005;font:12px Inter,system-ui,sans-serif}
`;
