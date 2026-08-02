import { describe, expect, it } from "vitest";

import { decryptSymmetricBytes, decryptSymmetricString, encryptSymmetricString, sha256Base64 } from "../src/crypto/bitwarden-crypto";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";

describe("encrypted login writes", () => {
  it("creates an item-key protected personal cipher with a verifiable URI checksum", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const payload = await createEncryptedLogin(
      {
        name: "Example",
        username: "person@example.com",
        password: "secret",
        uri: "https://example.com/login",
        notes: "personal",
        favorite: true,
      },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(payload.key as string, userKey);
    const login = payload.login as Record<string, unknown>;
    const uri = (login.uris as Array<Record<string, string>>)[0]!;

    await expect(decryptSymmetricString(payload.name as string, itemKey)).resolves.toBe("Example");
    await expect(decryptSymmetricString(login.username as string, itemKey)).resolves.toBe("person@example.com");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("secret");
    await expect(decryptSymmetricString(uri.uri!, itemKey)).resolves.toBe("https://example.com/login");
    await expect(decryptSymmetricString(uri.uriChecksum!, itemKey)).resolves.toBe(
      await sha256Base64("https://example.com/login"),
    );
    expect(payload.organizationId).toBeNull();
  });

  it("preserves protected login metadata while updating editable fields", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const original = await createEncryptedLogin(
      { name: "Old", username: "old", password: "old-pass", uri: "https://old.example" },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
    const totp = await encryptSymmetricString("otpauth://totp/test?secret=ABC", itemKey);
    const raw = { ...original, Id: "cipher-id", RevisionDate: "2026-08-01T00:00:00Z", Login: { ...(original.login as object), Totp: totp } };
    const updated = await updateEncryptedLogin(
      raw,
      { name: "New", username: "new", password: "new-pass", uri: "https://new.example" },
      userKey,
    );
    const login = updated.login as Record<string, unknown>;

    expect(login.totp).toBe(totp);
    expect(updated.lastKnownRevisionDate).toBe("2026-08-01T00:00:00Z");
    await expect(decryptSymmetricString(updated.name as string, itemKey)).resolves.toBe("New");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("new-pass");
  });

  it("refuses organization-owned cipher updates", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    await expect(
      updateEncryptedLogin(
        { organizationId: "org" },
        { name: "No", username: "", password: "", uri: "" },
        userKey,
      ),
    ).rejects.toThrow(/organization-owned/);
  });
});
