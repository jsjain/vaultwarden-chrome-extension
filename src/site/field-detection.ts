export interface UsernameFieldSignals {
  type: string;
  autocomplete: string;
  inputHint: string;
  contextHint: string;
  eligibleFieldCount: number;
}

const supportedTypes = new Set(["", "text", "email", "tel", "search"]);
const explicitUsername = /user[\s_-]*(?:name|id)|login[\s_-]*(?:name|id)|e[\s_-]*mail|email|identifier|account[\s_-]*name/;
const nonCredential = /search|query|one[\s_-]*time|otp|verification|security[\s_-]*code|captcha|coupon|promo/;
const loginContext = /sign[\s_-]*in|log[\s_-]*in|login|authenticate|authentication|session|continue|next/;

export function looksLikeUsernameField(signals: UsernameFieldSignals): boolean {
  const type = signals.type.toLowerCase();
  if (!supportedTypes.has(type)) return false;

  const autocomplete = signals.autocomplete.toLowerCase();
  const inputHint = signals.inputHint.toLowerCase();
  if (["username", "email"].includes(autocomplete)) return true;
  if (nonCredential.test(inputHint)) return false;
  if (type === "email" || explicitUsername.test(inputHint)) return true;
  if (type === "tel" && /phone|mobile/.test(inputHint)) return true;

  // Multi-step sign-in pages often use a generic text/identifier control before
  // rendering the password step. Treat it as a username only when it is the
  // sole plausible field in an explicitly login-shaped context.
  return type !== "search" && signals.eligibleFieldCount === 1 && loginContext.test(signals.contextHint.toLowerCase());
}

export function canBeUsernameField(typeInput: string, hintInput: string): boolean {
  const type = typeInput.toLowerCase();
  return supportedTypes.has(type) && type !== "search" && !nonCredential.test(hintInput.toLowerCase());
}
