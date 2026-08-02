export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const CHARACTER_SETS = {
  uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  lowercase: "abcdefghijkmnopqrstuvwxyz",
  numbers: "23456789",
  symbols: "!@#$%^&*_-+=",
} as const;

export function generatePassword(options: PasswordGeneratorOptions): string {
  if (!Number.isSafeInteger(options.length) || options.length < 4 || options.length > 128) {
    throw new Error("Password length must be between 4 and 128 characters.");
  }

  const enabledSets = [
    options.uppercase ? CHARACTER_SETS.uppercase : "",
    options.lowercase ? CHARACTER_SETS.lowercase : "",
    options.numbers ? CHARACTER_SETS.numbers : "",
    options.symbols ? CHARACTER_SETS.symbols : "",
  ].filter(Boolean);
  if (enabledSets.length === 0) {
    throw new Error("Select at least one character type.");
  }
  if (options.length < enabledSets.length) {
    throw new Error("Password length is too short for the selected character types.");
  }

  const alphabet = enabledSets.join("");
  const output = enabledSets.map((set) => set[randomIndex(set.length)]!);
  while (output.length < options.length) {
    output.push(alphabet[randomIndex(alphabet.length)]!);
  }
  for (let index = output.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [output[index], output[swapIndex]] = [output[swapIndex]!, output[index]!];
  }
  return output.join("");
}

function randomIndex(maximum: number): number {
  const limit = 256 - (256 % maximum);
  const value = new Uint8Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0]! >= limit);
  return value[0]! % maximum;
}
