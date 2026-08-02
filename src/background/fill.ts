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
    target: { tabId: tab.id },
    world: "ISOLATED",
    func: fillDocument,
    args: [item.username, item.password],
  });
  const result = results[0]?.result;
  if (!result || (!result.username && !result.password)) {
    throw new Error("No visible login fields were found on this page.");
  }
  return result;
}

function fillDocument(username: string, password: string): { username: boolean; password: boolean } {
  const visible = (element: HTMLInputElement): boolean => {
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return (
      !element.disabled &&
      !element.readOnly &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      bounds.width > 0 &&
      bounds.height > 0
    );
  };
  const inputs = [...document.querySelectorAll<HTMLInputElement>("input")].filter(visible);
  const passwordField = inputs.find(
    (input) => input.type.toLowerCase() === "password" && input.autocomplete !== "new-password",
  );
  const usernameField = inputs.find((input) => {
    const type = input.type.toLowerCase();
    const autocomplete = input.autocomplete.toLowerCase();
    return (
      input !== passwordField &&
      (autocomplete === "username" || autocomplete === "email" || type === "email" || type === "text")
    );
  });
  const setValue = (input: HTMLInputElement | undefined, value: string): boolean => {
    if (!input || !value) {
      return false;
    }
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  };
  const usernameFilled = setValue(usernameField, username);
  const passwordFilled = setValue(passwordField, password);
  (passwordField ?? usernameField)?.focus();
  return { username: usernameFilled, password: passwordFilled };
}
