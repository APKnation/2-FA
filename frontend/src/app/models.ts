
export interface User {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_verified: boolean;
  totp_enabled: boolean;
  created_at: string;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface LoginResponse {
  access_token?: string | null;
  refresh_token?: string | null;
  token_type?: string;
  expires_in?: number | null;
  requires_2fa: boolean;
  challenge_token?: string | null;
  message?: string | null;
}

export interface TwoFactorSetup {
  secret: string;
  provisioning_uri: string;
  qrcode: string;
}

export interface TwoFactorStatus {
  enabled: boolean;
  backup_codes_remaining: number;
}

export interface BackupCodes {
  codes: string[];
  message: string;
}
