import { describe, expect, it } from "vitest";

import { KdfType, parseKdfConfig } from "../src/shared/kdf";

describe("parseKdfConfig", () => {
  it("parses a PascalCase PBKDF2 response", () => {
    expect(parseKdfConfig({ Kdf: 0, KdfIterations: 600_000 })).toEqual({
      type: KdfType.Pbkdf2Sha256,
      iterations: 600_000,
    });
  });

  it("parses a camelCase Argon2id response", () => {
    expect(
      parseKdfConfig({
        kdf: 1,
        kdfIterations: 3,
        kdfMemory: 64,
        kdfParallelism: 4,
      }),
    ).toEqual({
      type: KdfType.Argon2id,
      iterations: 3,
      memoryMiB: 64,
      parallelism: 4,
    });
  });

  it("rejects downgrade parameters", () => {
    expect(() => parseKdfConfig({ Kdf: 0, KdfIterations: 1_000 })).toThrow(/downgrade/);
    expect(() =>
      parseKdfConfig({ Kdf: 1, KdfIterations: 1, KdfMemory: 8, KdfParallelism: 1 }),
    ).toThrow(/downgrade/);
  });

  it("rejects resource-exhaustion parameters", () => {
    expect(() => parseKdfConfig({ Kdf: 0, KdfIterations: 20_000_000 })).toThrow(
      /safety limit/,
    );
    expect(() =>
      parseKdfConfig({ Kdf: 1, KdfIterations: 3, KdfMemory: 2048, KdfParallelism: 4 }),
    ).toThrow(/safety limit/);
  });
});
