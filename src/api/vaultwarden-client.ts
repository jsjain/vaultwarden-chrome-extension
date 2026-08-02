import {
  BITWARDEN_PROTOCOL_VERSION,
  CLIENT_NAME,
  DEVICE_TYPE_CHROME_EXTENSION,
  REQUEST_TIMEOUT_MS,
} from "../shared/constants";
import { normalizeServerEnvironment } from "../shared/environment";
import { parseKdfConfig, type KdfConfig } from "../shared/kdf";
import { ApiError } from "./api-error";
import type { LoginResult, PasswordLoginInput, RefreshResult, SyncResponse } from "./models";

type Fetch = typeof fetch;

interface ServerConfigResponse {
  version?: unknown;
  object?: unknown;
}

export interface ServerCheckResult {
  baseUrl: string;
  serverVersion?: string;
}

export interface PreloginResult {
  kdf: KdfConfig;
  endpoint: "password" | "legacy";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class VaultwardenClient {
  constructor(private readonly fetchImpl: Fetch = globalThis.fetch.bind(globalThis)) {}

  async checkServer(baseUrl: string): Promise<ServerCheckResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchJson(`${environment.apiUrl}/config`, { method: "GET" });
    if (!isRecord(response)) {
      throw new ApiError("The server config endpoint returned an invalid response.");
    }

    const config = response as ServerConfigResponse;
    const serverVersion = typeof config.version === "string" ? config.version : undefined;
    return {
      baseUrl: environment.baseUrl,
      ...(serverVersion === undefined ? {} : { serverVersion }),
    };
  }

  async getPrelogin(baseUrl: string, emailInput: string): Promise<PreloginResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const email = emailInput.trim().toLowerCase();
    if (!email || !email.includes("@") || /\s/.test(email)) {
      throw new Error("Enter a valid account email address.");
    }

    const body = JSON.stringify({ email });
    try {
      const response = await this.fetchJson(`${environment.identityUrl}/accounts/prelogin/password`, {
        method: "POST",
        body,
      });
      return { kdf: parseKdfConfig(response), endpoint: "password" };
    } catch (error) {
      if (!(error instanceof ApiError) || (error.status !== 404 && error.status !== 405)) {
        throw error;
      }
    }

    const legacyResponse = await this.fetchJson(`${environment.identityUrl}/accounts/prelogin`, {
      method: "POST",
      body,
    });
    return { kdf: parseKdfConfig(legacyResponse), endpoint: "legacy" };
  }

  async loginWithPassword(input: PasswordLoginInput): Promise<LoginResult> {
    const environment = normalizeServerEnvironment(input.baseUrl);
    const form = new URLSearchParams({
      grant_type: "password",
      username: input.email.trim().toLowerCase(),
      password: input.masterPasswordHash,
      scope: "api offline_access",
      client_id: CLIENT_NAME,
      deviceType: DEVICE_TYPE_CHROME_EXTENSION,
      deviceIdentifier: input.deviceIdentifier,
      deviceName: "Chrome",
    });
    if (input.twoFactorProvider !== undefined && input.twoFactorToken) {
      form.set("twoFactorProvider", String(input.twoFactorProvider));
      form.set("twoFactorToken", input.twoFactorToken);
      form.set("twoFactorRemember", input.twoFactorRemember ? "1" : "0");
    }
    if (input.newDeviceOtp) {
      form.set("newDeviceOtp", input.newDeviceOtp);
    }

    const response = await this.fetchRaw(`${environment.identityUrl}/connect/token`, {
      method: "POST",
      body: form.toString(),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Device-Type": DEVICE_TYPE_CHROME_EXTENSION,
      },
    });
    const payload = await parseJsonRecord(response);

    if (response.ok) {
      const accessToken = stringProperty(payload, "access_token");
      const tokenType = stringProperty(payload, "token_type");
      if (!accessToken || !tokenType) {
        throw new ApiError("The identity server returned an invalid access token response.");
      }
      const wrappedUserKey = extractWrappedUserKey(payload);
      if (!wrappedUserKey) {
        throw new ApiError("This account did not return a master-password wrapped user key.");
      }
      const kdf = parseIdentityKdf(payload);
      const refreshToken = stringProperty(payload, "refresh_token");
      const privateKey = stringProperty(payload, "PrivateKey");
      const expiresIn = numberProperty(payload, "expires_in");
      return {
        kind: "success",
        accessToken,
        wrappedUserKey,
        kdf,
        ...(refreshToken === undefined ? {} : { refreshToken }),
        ...(privateKey === undefined ? {} : { privateKey }),
        ...(expiresIn === undefined ? {} : { expiresIn }),
      };
    }

    const providers = recordProperty(payload, "TwoFactorProviders2");
    if (response.status === 400 && providers && Object.keys(providers).length > 0) {
      const providerDetails: Record<string, Record<string, string>> = {};
      for (const [key, value] of Object.entries(providers)) {
        if (isRecord(value)) {
          providerDetails[key] = Object.fromEntries(
            Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
          );
        }
      }
      return {
        kind: "two-factor",
        providers: Object.keys(providers)
          .map((value) => Number.parseInt(value, 10))
          .filter(Number.isInteger),
        providerDetails,
      };
    }

    const errorModel = recordProperty(payload, "ErrorModel");
    const message = firstNonEmptyString(
      errorModel ? stringProperty(errorModel, "Message") : undefined,
      stringProperty(payload, "Message"),
      stringProperty(payload, "error_description"),
    );
    if (response.status === 400 && message?.toLowerCase().includes("new device verification")) {
      return { kind: "device-verification", message };
    }
    throw new ApiError(message ?? `Login failed with HTTP ${response.status}.`, response.status);
  }

  async getSync(baseUrl: string, accessToken: string): Promise<SyncResponse> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchJson(`${environment.apiUrl}/sync?excludeDomains=true`, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!isRecord(response)) {
      throw new ApiError("The vault sync endpoint returned an invalid response.");
    }
    return response as SyncResponse;
  }

  async getCipher(baseUrl: string, accessToken: string, id: string): Promise<Record<string, unknown>> {
    return this.authenticatedRecord(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}`, "GET");
  }

  async createCipher(
    baseUrl: string,
    accessToken: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authenticatedRecord(baseUrl, accessToken, "/ciphers", "POST", payload);
  }

  async updateCipher(
    baseUrl: string,
    accessToken: string,
    id: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authenticatedRecord(
      baseUrl,
      accessToken,
      `/ciphers/${encodeURIComponent(id)}`,
      "PUT",
      payload,
    );
  }

  async refreshAccessToken(baseUrl: string, refreshToken: string): Promise<RefreshResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CLIENT_NAME,
      refresh_token: refreshToken,
    });
    const response = await this.fetchRaw(`${environment.identityUrl}/connect/token`, {
      method: "POST",
      body: form.toString(),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Device-Type": DEVICE_TYPE_CHROME_EXTENSION,
      },
    });
    const payload = await parseJsonRecord(response);
    if (!response.ok) {
      throw new ApiError("The account session expired. Sign in again.", response.status);
    }
    const accessToken = stringProperty(payload, "access_token");
    if (!accessToken) {
      throw new ApiError("The identity server returned an invalid refresh response.");
    }
    const nextRefreshToken = stringProperty(payload, "refresh_token");
    const expiresIn = numberProperty(payload, "expires_in");
    return {
      accessToken,
      ...(nextRefreshToken === undefined ? {} : { refreshToken: nextRefreshToken }),
      ...(expiresIn === undefined ? {} : { expiresIn }),
    };
  }

  async sendTwoFactorEmail(
    baseUrl: string,
    email: string,
    masterPasswordHash: string,
    deviceIdentifier: string,
  ): Promise<void> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchRaw(`${environment.apiUrl}/two-factor/send-email-login`, {
      method: "POST",
      body: JSON.stringify({ email, masterPasswordHash, deviceIdentifier }),
    });
    if (!response.ok) {
      throw new ApiError(`Email verification request failed with HTTP ${response.status}.`, response.status);
    }
  }

  private async fetchJson(url: string, init: RequestInit): Promise<unknown> {
    const response = await this.fetchRaw(url, init);
    if (!response.ok) {
      throw new ApiError(`Server request failed with HTTP ${response.status}.`, response.status);
    }
    return parseJson(response);
  }

  private async authenticatedRecord(
    baseUrl: string,
    accessToken: string,
    path: string,
    method: "GET" | "POST" | "PUT",
    payload?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const environment = normalizeServerEnvironment(baseUrl);
    const value = await this.fetchJson(`${environment.apiUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${accessToken}` },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    });
    if (!isRecord(value)) {
      throw new ApiError("The server returned an invalid cipher response.");
    }
    return value;
  }

  private async fetchRaw(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json; charset=utf-8",
          "Bitwarden-Client-Name": CLIENT_NAME,
          "Bitwarden-Client-Version": BITWARDEN_PROTOCOL_VERSION,
          "Device-Type": DEVICE_TYPE_CHROME_EXTENSION,
          ...init.headers,
        },
      });

      return response;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ApiError("The server request timed out.");
      }
      throw new ApiError("Could not connect to the server.");
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function parseJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ApiError("Server returned a non-JSON response.", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError("Server returned malformed JSON.", response.status);
  }
}

async function parseJsonRecord(response: Response): Promise<Record<string, unknown>> {
  const value = await parseJson(response);
  if (!isRecord(value)) {
    throw new ApiError("The identity server returned an invalid response.", response.status);
  }
  return value;
}

function parseIdentityKdf(payload: Record<string, unknown>): KdfConfig {
  return parseKdfConfig({
    Kdf: payload.Kdf,
    KdfIterations: payload.KdfIterations,
    KdfMemory: payload.KdfMemory,
    KdfParallelism: payload.KdfParallelism,
  });
}

function extractWrappedUserKey(payload: Record<string, unknown>): string | undefined {
  const legacy = stringProperty(payload, "Key");
  if (legacy) {
    return legacy;
  }
  const options = recordProperty(payload, "UserDecryptionOptions");
  const unlock = options ? recordProperty(options, "MasterPasswordUnlock") : undefined;
  return unlock ? stringProperty(unlock, "MasterKeyEncryptedUserKey") : undefined;
}

function stringProperty(value: Record<string, unknown>, key: string): string | undefined {
  const result = responseProperty(value, key);
  return typeof result === "string" ? result : undefined;
}

function numberProperty(value: Record<string, unknown>, key: string): number | undefined {
  const result = responseProperty(value, key);
  return typeof result === "number" ? result : undefined;
}

function recordProperty(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const result = responseProperty(value, key);
  return isRecord(result) ? result : undefined;
}

function responseProperty(value: Record<string, unknown>, key: string): unknown {
  if (Object.hasOwn(value, key)) {
    return value[key];
  }
  const normalizedKey = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const match = Object.keys(value).find(
    (candidate) => candidate.replace(/[^a-z0-9]/gi, "").toLowerCase() === normalizedKey,
  );
  return match === undefined ? undefined : value[match];
}

function firstNonEmptyString(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => value !== undefined && value.trim().length > 0);
}
