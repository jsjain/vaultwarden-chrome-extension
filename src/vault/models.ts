export interface VaultUri {
  uri: string;
  match?: number;
}

export interface VaultItem {
  id: string;
  name: string;
  username: string;
  password: string;
  totp?: string;
  notes?: string;
  favorite: boolean;
  reprompt: boolean;
  organizationId?: string;
  uris: VaultUri[];
}

export interface VaultItemSummary {
  id: string;
  name: string;
  username: string;
  favorite: boolean;
  requiresReprompt: boolean;
  editable: boolean;
  matched: boolean;
  uri?: string;
}

export interface VaultItemDetail extends VaultItemSummary {
  password: string;
  hasTotp: boolean;
  protected: boolean;
  notes?: string;
  uris: VaultUri[];
}
