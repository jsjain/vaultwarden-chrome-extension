import type { KdfConfig } from "../shared/kdf";

export interface TwoFactorChallenge {
  kind: "two-factor";
  providers: number[];
  providerDetails: Record<string, Record<string, string>>;
}

export interface DeviceVerificationChallenge {
  kind: "device-verification";
  message: string;
}

export interface LoginSuccess {
  kind: "success";
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  wrappedUserKey: string;
  privateKey?: string;
  kdf: KdfConfig;
}

export type LoginResult = LoginSuccess | TwoFactorChallenge | DeviceVerificationChallenge;

export interface PasswordLoginInput {
  baseUrl: string;
  email: string;
  masterPasswordHash: string;
  deviceIdentifier: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: boolean;
  newDeviceOtp?: string;
}

export interface SyncResponse {
  Profile?: {
    Id?: unknown;
    Email?: unknown;
    PrivateKey?: unknown;
    Organizations?: unknown;
    OrganizationsNew?: unknown;
  };
  Ciphers?: unknown;
  Folders?: unknown;
  profile?: SyncResponse["Profile"];
  ciphers?: unknown;
  folders?: unknown;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}
