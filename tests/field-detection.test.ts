import { describe, expect, it } from "vitest";

import { looksLikeUsernameField } from "../src/site/field-detection";

const base = {
  type: "text",
  autocomplete: "",
  inputHint: "",
  contextHint: "",
  eligibleFieldCount: 1,
};

describe("username field detection", () => {
  it("recognizes the AWS-style username control", () => {
    expect(looksLikeUsernameField({
      ...base,
      autocomplete: "on",
      inputHint: "on username username username",
      contextHint: "Sign in Next",
    })).toBe(true);
  });

  it("recognizes generic single-field multi-step sign-in forms", () => {
    expect(looksLikeUsernameField({
      ...base,
      inputHint: "principal",
      contextHint: "/platform/tenant/login Continue",
    })).toBe(true);
  });

  it("recognizes identifier and associated-label signals", () => {
    expect(looksLikeUsernameField({ ...base, inputHint: "account identifier" })).toBe(true);
    expect(looksLikeUsernameField({ ...base, inputHint: "Corporate user ID" })).toBe(true);
  });

  it("does not treat search, OTP, or ambiguous multi-field controls as usernames", () => {
    expect(looksLikeUsernameField({ ...base, type: "search", inputHint: "search", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "verification code", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "customer", contextHint: "Sign in", eligibleFieldCount: 2 })).toBe(false);
  });
});
