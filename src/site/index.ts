import type { ExtensionRequest, ExtensionResponse, ResponseData } from "../shared/messages";

const marker = "data-leanvault-loaded";
if (!document.documentElement.hasAttribute(marker)) {
  document.documentElement.setAttribute(marker, "true");
  void initialize();
}

async function initialize(): Promise<void> {
  document.addEventListener("submit", captureLogin, true);
  document.addEventListener("click", captureSubmitClick, true);
  try {
    const [suggestions, pending] = await Promise.all([
      request({ type: "site.suggestions", url: location.href }),
      request({ type: "site.pendingPrompt" }),
    ]);
    if (suggestions.type === "siteSuggestions" && suggestions.items.length > 0 && findPasswordField()) {
      renderSuggestions(suggestions.items);
    }
    if (pending.type === "sitePrompt" && pending.prompt) renderSavePrompt(pending.prompt);
  } catch {
    // Locked/signed-out vaults stay silent on the page.
  }
}

function renderSuggestions(items: Array<{ id: string; name: string; username: string }>): void {
  const host = overlayHost("leanvault-suggestions");
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><button class="badge" type="button">L · ${items.length} login${items.length === 1 ? "" : "s"}</button><div class="menu" hidden></div>`;
  const badge = root.querySelector<HTMLButtonElement>(".badge")!;
  const menu = root.querySelector<HTMLDivElement>(".menu")!;
  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "choice";
    button.textContent = `${item.name}${item.username ? ` · ${item.username}` : ""}`;
    button.addEventListener("click", () => void fill(item.id, host));
    menu.append(button);
  }
  badge.addEventListener("click", () => { menu.hidden = !menu.hidden; });
}

async function fill(id: string, host: HTMLElement): Promise<void> {
  try {
    const data = await request({ type: "site.credential", id, url: location.href });
    if (data.type !== "siteCredential") return;
    const password = findPasswordField();
    const username = findUsernameField(password?.form ?? null, password);
    setInputValue(username, data.username);
    setInputValue(password, data.password);
    (password ?? username)?.focus();
    host.remove();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "LeanVault could not fill this login.");
  }
}

let lastCapture = "";
function captureLogin(event: Event): void {
  const form = event.target instanceof HTMLFormElement ? event.target : null;
  if (form) void inspectForm(form);
}

function captureSubmitClick(event: Event): void {
  const target = event.target instanceof Element ? event.target.closest("button,input") : null;
  if (!(target instanceof HTMLButtonElement || target instanceof HTMLInputElement)) return;
  const type = target.type.toLowerCase();
  if (type !== "submit" && !(target instanceof HTMLButtonElement && type === "")) return;
  if (target.form) void inspectForm(target.form);
}

async function inspectForm(form: HTMLFormElement): Promise<void> {
  const passwordField = [...form.querySelectorAll<HTMLInputElement>('input[type="password"]')]
    .filter(visible)
    .at(-1);
  if (!passwordField?.value) return;
  const username = findUsernameField(form, passwordField)?.value ?? "";
  const fingerprint = `${location.origin}\0${username}\0${passwordField.value}`;
  if (fingerprint === lastCapture) return;
  lastCapture = fingerprint;
  setTimeout(() => { lastCapture = ""; }, 3_000);
  try {
    const data = await request({
      type: "site.inspect",
      url: location.href,
      username,
      password: passwordField.value,
    });
    if (data.type === "sitePrompt" && data.prompt) renderSavePrompt(data.prompt);
  } catch {
    // Form submission should never be interrupted by the password manager.
  }
}

function renderSavePrompt(prompt: { id: string; action: "save" | "update"; name: string }): void {
  document.getElementById("leanvault-save-prompt")?.remove();
  const host = overlayHost("leanvault-save-prompt");
  const root = host.shadowRoot!;
  root.innerHTML = `<style>${styles}</style><div class="prompt"><strong>${prompt.action === "update" ? "Update" : "Save"} login?</strong><span>${escapeText(prompt.name)}</span><div><button class="dismiss" type="button">Not now</button><button class="save" type="button">${prompt.action === "update" ? "Update" : "Save"}</button></div></div>`;
  root.querySelector<HTMLButtonElement>(".save")!.addEventListener("click", async () => {
    try {
      await request({ type: "site.save", promptId: prompt.id });
      host.remove();
      showTransient(prompt.action === "update" ? "Login updated." : "Login saved.");
    } catch (error) {
      showTransient(error instanceof Error ? error.message : "LeanVault could not save this login.");
    }
  });
  root.querySelector<HTMLButtonElement>(".dismiss")!.addEventListener("click", () => {
    void request({ type: "site.dismiss", promptId: prompt.id });
    host.remove();
  });
}

function overlayHost(id: string): HTMLDivElement {
  document.getElementById(id)?.remove();
  const host = document.createElement("div");
  host.id = id;
  host.style.cssText = "all:initial;position:fixed;right:18px;bottom:18px;z-index:2147483647";
  host.attachShadow({ mode: "open" });
  document.documentElement.append(host);
  return host;
}

function showTransient(message: string): void {
  const host = overlayHost("leanvault-toast");
  host.shadowRoot!.innerHTML = `<style>${styles}</style><div class="toast">${escapeText(message)}</div>`;
  setTimeout(() => host.remove(), 3_500);
}

function findPasswordField(): HTMLInputElement | undefined {
  return [...document.querySelectorAll<HTMLInputElement>('input[type="password"]')].find(visible);
}

function findUsernameField(form: HTMLFormElement | null, password?: HTMLInputElement): HTMLInputElement | undefined {
  const scope: ParentNode = form ?? document;
  const inputs = [...scope.querySelectorAll<HTMLInputElement>("input")].filter(visible);
  return inputs.find((input) => {
    const type = input.type.toLowerCase();
    const autocomplete = input.autocomplete.toLowerCase();
    return input !== password && (autocomplete === "username" || autocomplete === "email" || type === "email");
  }) ?? inputs.find((input) => input !== password && input.type.toLowerCase() === "text");
}

function visible(input: HTMLInputElement): boolean {
  const bounds = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return !input.disabled && !input.readOnly && bounds.width > 0 && bounds.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

function setInputValue(input: HTMLInputElement | undefined, value: string): boolean {
  if (!input || !value) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

async function request(value: ExtensionRequest): Promise<ResponseData> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) throw new Error("LeanVault is unavailable.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

function escapeText(value: string): string {
  const span = document.createElement("span");
  span.textContent = value;
  return span.innerHTML;
}

const styles = `
  *{box-sizing:border-box;font-family:Inter,system-ui,sans-serif}
  button{border:0;border-radius:9px;cursor:pointer;font-size:12px;font-weight:700}
  .badge{padding:10px 13px;background:#2f6fed;color:#fff;box-shadow:0 5px 20px #0003}
  .menu{position:absolute;right:0;bottom:44px;width:270px;padding:7px;border:1px solid #dce3ef;border-radius:12px;background:#fff;box-shadow:0 8px 30px #0003}
  .choice{display:block;width:100%;padding:10px;text-align:left;background:#fff;color:#172033;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .choice:hover{background:#eef4ff}
  .prompt{width:300px;padding:14px;border:1px solid #dce3ef;border-radius:13px;background:#fff;color:#172033;box-shadow:0 8px 30px #0003}
  .prompt strong,.prompt span{display:block;margin-bottom:6px}.prompt span{color:#667085;font-size:11px}.prompt div{display:flex;justify-content:flex-end;gap:7px;margin-top:11px}
  .prompt button{padding:8px 12px}.save{background:#2f6fed;color:#fff}.dismiss{background:#eaf0fa;color:#234c9b}
  .toast{max-width:330px;padding:11px 14px;border-radius:10px;background:#172033;color:#fff;box-shadow:0 5px 20px #0003;font:12px Inter,system-ui,sans-serif}
`;
