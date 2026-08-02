import { describe, expect, it } from "vitest";

import { isExtensionRequest } from "../src/shared/messages";
import { isVaultTimeoutMinutes } from "../src/shared/settings";

describe("vault timeout settings", () => {
  it("accepts only supported timeout values", () => {
    expect([-1, 0, 15, 60, 240].every(isVaultTimeoutMinutes)).toBe(true);
    expect(isVaultTimeoutMinutes(30)).toBe(false);
    expect(isVaultTimeoutMinutes("60")).toBe(false);
  });

  it("validates vault-timeout runtime messages", () => {
    expect(isExtensionRequest({ type: "settings.vaultTimeout", minutes: -1 })).toBe(true);
    expect(isExtensionRequest({ type: "settings.vaultTimeout", minutes: 30 })).toBe(false);
  });
});
