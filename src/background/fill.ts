import type { VaultItem } from "../vault/models";

export async function fillActiveTab(item: VaultItem): Promise<{ username: boolean; password: boolean }> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined || !tab.url || !/^https?:\/\//i.test(tab.url)) {
    throw new Error("Open an HTTP or HTTPS login page before filling.");
  }
  if (new URL(tab.url).protocol === "http:" && item.uris.some(({ uri }) => /^https:\/\//i.test(uri))) {
    throw new Error("Refusing to fill an HTTPS login into an insecure HTTP page.");
  }
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    world: "ISOLATED",
    func: fillDocument,
    args: [
      item.username,
      item.password,
      [...new Set([new URL(tab.url).origin, ...item.uris.flatMap(({ uri }) => {
        try { return [new URL(uri).origin]; } catch { return []; }
      })])],
    ],
  });
  const result = results.reduce(
    (filled, frame) => ({
      username: filled.username || Boolean(frame.result?.username),
      password: filled.password || Boolean(frame.result?.password),
    }),
    { username: false, password: false },
  );
  if (!result.username && !result.password) {
    throw new Error("No visible login fields were found on this page.");
  }
  return result;
}

function fillDocument(username: string, password: string, allowedOrigins: string[]): { username: boolean; password: boolean } {
  if (!allowedOrigins.includes(location.origin)) return { username: false, password: false };
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  const visible = (element: HTMLInputElement): boolean => {
    if (element.disabled || element.readOnly || element.type.toLowerCase() === "hidden") return false;
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity || "1") > 0 &&
      bounds.width > 1 && bounds.height > 1 && element.getClientRects().length > 0;
  };
  const inputs = roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(visible);
  const passwords = inputs.filter((input) => input.type.toLowerCase() === "password");
  const passwordField = passwords.find((input) => input.autocomplete.toLowerCase() === "current-password") ??
    passwords.find((input) => input.autocomplete.toLowerCase() !== "new-password") ?? passwords[0];
  const usernameCandidates = inputs.filter((input) => {
    const type = input.type.toLowerCase();
    return input !== passwordField && ["", "text", "email", "tel", "search"].includes(type);
  });
  const score = (input: HTMLInputElement): number => {
    const hint = `${input.autocomplete} ${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`.toLowerCase();
    let value = 0;
    if (/username|user-name|login|email|e-mail/.test(hint)) value += 12;
    if (input.autocomplete === "username" || input.autocomplete === "email") value += 15;
    if (input.type === "email") value += 10;
    if (/search|otp|code|phone|mobile|captcha/.test(hint)) value -= 15;
    if (passwordField && input.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING) value += 3;
    return value;
  };
  const usernameField = usernameCandidates.sort((left, right) => score(right) - score(left))[0];
  const setValue = (input: HTMLInputElement | undefined, value: string): boolean => {
    if (!input || !value) return false;
    input.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(input, value);
    try {
      input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    } catch {
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new Event("blur", { bubbles: true }));
    return input.value === value;
  };
  const usernameFilled = setValue(usernameField, username);
  const passwordFilled = setValue(passwordField, password);
  (passwordField ?? usernameField)?.focus();
  return { username: usernameFilled, password: passwordFilled };
}
