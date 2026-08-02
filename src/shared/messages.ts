import type { ServerSnapshot } from "./storage-types";
import type { VaultItemDetail, VaultItemSummary } from "../vault/models";
import type { LoginWriteInput } from "../vault/encrypt-login";
import {
  isBrowserIntegrationOptions,
  isGeneratorOptions,
  isVaultTimeoutMinutes,
  type BrowserIntegrationOptions,
  type StoredGeneratorOptions,
  type VaultTimeoutMinutes,
} from "./settings";

export type { ServerSnapshot } from "./storage-types";

export type PublicAppState =
  | { phase: "setup" }
  | { phase: "signed-out"; snapshot: ServerSnapshot; email?: string }
  | {
      phase: "locked";
      snapshot: ServerSnapshot;
      email: string;
      itemCount: number;
      lastSync?: string;
    }
  | {
      phase: "unlocked";
      snapshot: ServerSnapshot;
      email: string;
      itemCount: number;
      decryptionFailures: number;
      lastSync?: string;
    };

export interface AuthLoginRequest {
  type: "auth.login";
  baseUrl: string;
  email: string;
  masterPassword: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: boolean;
  newDeviceOtp?: string;
}

export interface VaultListRequest {
  type: "vault.list";
  query: string;
  currentUrl?: string;
}

export type ExtensionRequest =
  | { type: "app.getState" }
  | { type: "server.check"; baseUrl: string }
  | AuthLoginRequest
  | { type: "auth.sendEmailCode"; baseUrl: string; email: string; masterPassword: string }
  | { type: "auth.unlock"; masterPassword: string }
  | { type: "auth.lock" }
  | { type: "auth.logout" }
  | { type: "vault.sync" }
  | VaultListRequest
  | { type: "vault.get"; id: string; currentUrl?: string }
  | { type: "vault.authorize"; id: string; masterPassword: string }
  | { type: "vault.totp"; id: string }
  | { type: "vault.fill"; id: string }
  | { type: "vault.create"; login: LoginWriteInput }
  | { type: "vault.update"; id: string; login: LoginWriteInput }
  | { type: "settings.get" }
  | { type: "settings.siteIntegration"; enabled: boolean }
  | { type: "settings.vaultTimeout"; minutes: VaultTimeoutMinutes }
  | { type: "settings.browserOptions"; options: BrowserIntegrationOptions }
  | { type: "settings.generator"; options: StoredGeneratorOptions }
  | { type: "site.suggestions"; url: string }
  | { type: "site.credential"; id: string; url: string }
  | { type: "site.inspect"; url: string; username: string; password: string }
  | { type: "site.pendingPrompt" }
  | { type: "site.generatePassword"; url: string }
  | { type: "site.save"; promptId: string; login?: LoginWriteInput }
  | { type: "site.dismiss"; promptId: string };

export type ResponseData =
  | { type: "state"; state: PublicAppState }
  | { type: "server"; snapshot: ServerSnapshot }
  | {
      type: "login";
      result:
        | { status: "unlocked"; itemCount: number; failures: number }
        | {
            status: "two-factor";
            providers: number[];
            providerDetails: Record<string, Record<string, string>>;
          }
        | { status: "device-verification"; message: string };
    }
  | { type: "unlock"; itemCount: number; failures: number }
  | { type: "done" }
  | { type: "sync"; itemCount: number; failures: number }
  | { type: "items"; items: VaultItemSummary[] }
  | { type: "item"; item: VaultItemDetail }
  | { type: "totp"; code: string; period: number; remaining: number }
  | { type: "fill"; username: boolean; password: boolean }
  | {
      type: "settings";
      siteIntegrationEnabled: boolean;
      vaultTimeoutMinutes: VaultTimeoutMinutes;
      browserOptions: BrowserIntegrationOptions;
      generatorOptions: StoredGeneratorOptions;
    }
  | { type: "siteSuggestions"; items: VaultItemSummary[] }
  | { type: "siteCredential"; username: string; password: string }
  | { type: "generatedPassword"; password: string }
  | {
      type: "sitePrompt";
      prompt: ({ id: string; action: "save" | "update" } & LoginWriteInput) | null;
    };

export type ExtensionResponse = { ok: true; data: ResponseData } | { ok: false; error: string };

export function isExtensionRequest(value: unknown): value is ExtensionRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const request = value as Record<string, unknown>;
  switch (request.type) {
    case "app.getState":
    case "auth.lock":
    case "auth.logout":
    case "vault.sync":
      return true;
    case "server.check":
      return boundedString(request.baseUrl, 2_048);
    case "auth.login":
      return (
        boundedString(request.baseUrl, 2_048) &&
        boundedString(request.email, 320) &&
        boundedString(request.masterPassword, 1_024) &&
        optionalInteger(request.twoFactorProvider) &&
        optionalString(request.twoFactorToken, 4_096) &&
        (request.twoFactorRemember === undefined || typeof request.twoFactorRemember === "boolean") &&
        optionalString(request.newDeviceOtp, 4_096)
      );
    case "auth.unlock":
      return boundedString(request.masterPassword, 1_024);
    case "auth.sendEmailCode":
      return (
        boundedString(request.baseUrl, 2_048) &&
        boundedString(request.email, 320) &&
        boundedString(request.masterPassword, 1_024)
      );
    case "vault.list":
      return (
        typeof request.query === "string" &&
        request.query.length <= 200 &&
        optionalString(request.currentUrl, 8_192)
      );
    case "vault.get":
      return boundedString(request.id, 128) && optionalString(request.currentUrl, 8_192);
    case "vault.authorize":
      return boundedString(request.id, 128) && boundedString(request.masterPassword, 1_024);
    case "vault.fill":
    case "vault.totp":
      return boundedString(request.id, 128);
    case "vault.create":
      return validLogin(request.login);
    case "vault.update":
      return boundedString(request.id, 128) && validLogin(request.login);
    case "settings.get":
    case "site.pendingPrompt":
      return true;
    case "settings.siteIntegration":
      return typeof request.enabled === "boolean";
    case "settings.vaultTimeout":
      return isVaultTimeoutMinutes(request.minutes);
    case "settings.browserOptions":
      return isBrowserIntegrationOptions(request.options);
    case "settings.generator":
      return isGeneratorOptions(request.options);
    case "site.suggestions":
      return boundedString(request.url, 8_192);
    case "site.credential":
      return boundedString(request.id, 128) && boundedString(request.url, 8_192);
    case "site.inspect":
      return (
        boundedString(request.url, 8_192) &&
        optionalString(request.username, 1_000) &&
        boundedString(request.password, 10_000)
      );
    case "site.generatePassword":
      return boundedString(request.url, 8_192);
    case "site.save":
      return boundedString(request.promptId, 128) && (request.login === undefined || validLogin(request.login));
    case "site.dismiss":
      return boundedString(request.promptId, 128);
    default:
      return false;
  }
}

function validLogin(value: unknown): value is LoginWriteInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const login = value as Record<string, unknown>;
  return (
    boundedString(login.name, 1_000) &&
    optionalString(login.username, 1_000) &&
    optionalString(login.password, 10_000) &&
    optionalString(login.uri, 8_192) &&
    optionalString(login.notes, 10_000) &&
    (login.favorite === undefined || typeof login.favorite === "boolean")
  );
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function optionalString(value: unknown, maximum: number): boolean {
  return value === undefined || (typeof value === "string" && value.length <= maximum);
}

function optionalInteger(value: unknown): boolean {
  return value === undefined || Number.isSafeInteger(value);
}
