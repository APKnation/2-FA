import { Injectable, signal } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import {
  BackupCodes,
  LoginResponse,
  TokenPair,
  TwoFactorSetup,
  TwoFactorStatus,
  User,
} from '../models';

const API_STORAGE_KEY = 'secureauth.apiBase';
const ACCESS_STORAGE_KEY = 'secureauth.accessToken';
const REFRESH_STORAGE_KEY = 'secureauth.refreshToken';

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  auth?: boolean;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly apiBaseSignal = signal(this.readApiBase());
  readonly apiBase = this.apiBaseSignal.asReadonly();

  readonly accessToken = signal<string | null>(this.readStorage(ACCESS_STORAGE_KEY));
  readonly refreshToken = signal<string | null>(this.readStorage(REFRESH_STORAGE_KEY));
  readonly user = signal<User | null>(null);
  readonly challengeToken = signal<string | null>(null);
  readonly pendingEmail = signal<string | null>(null);
  readonly challengeEmailSent = signal(false);

  constructor(private http: HttpClient) {}

  // ------------------------------------------------------------------
  // Configuration / session helpers
  // ------------------------------------------------------------------
  private readApiBase(): string {
    try {
      const stored = localStorage.getItem(API_STORAGE_KEY);
      return stored ? stored.replace(/\/$/, '') : '/api/v1';
    } catch {
      return '/api/v1';
    }
  }

  private readStorage(key: string): string | null {
    try {
      return sessionStorage.getItem(key);
    } catch {
      return null;
    }
  }

  private writeStorage(key: string, value: string | null): void {
    try {
      if (value === null) {
        sessionStorage.removeItem(key);
      } else {
        sessionStorage.setItem(key, value);
      }
    } catch {
      // Storage can be unavailable (private mode); the session still works in memory.
    }
  }

  setApiBase(url: string): void {
    const normalized = url.trim().replace(/\/$/, '') || '/api/v1';
    this.apiBaseSignal.set(normalized);
    try {
      localStorage.setItem(API_STORAGE_KEY, normalized);
    } catch {
      // Storage can be unavailable (private mode); the in-memory value still applies.
    }
  }

  private setTokens(access: string, refresh: string): void {
    this.accessToken.set(access);
    this.refreshToken.set(refresh);
    this.writeStorage(ACCESS_STORAGE_KEY, access);
    this.writeStorage(REFRESH_STORAGE_KEY, refresh);
  }

  clearSession(): void {
    this.accessToken.set(null);
    this.refreshToken.set(null);
    this.user.set(null);
    this.challengeToken.set(null);
    this.pendingEmail.set(null);
    this.challengeEmailSent.set(false);
    this.writeStorage(ACCESS_STORAGE_KEY, null);
    this.writeStorage(REFRESH_STORAGE_KEY, null);
  }

  // ------------------------------------------------------------------
  // HTTP
  // ------------------------------------------------------------------
  private headers(auth: boolean): HttpHeaders {
    let headers = new HttpHeaders({ 'Content-Type': 'application/json' });
    if (auth && this.accessToken()) {
      headers = headers.set('Authorization', `Bearer ${this.accessToken()}`);
    }
    return headers;
  }

  private errorMessage(error: unknown): string {
    const err = error as { error?: { detail?: unknown }; message?: string };
    const detail = err?.error?.detail;
    if (typeof detail === 'string' && detail.length > 0) {
      return detail;
    }
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map((item) => (item as { msg?: string })?.msg || 'Invalid input').join(', ');
    }
    return err?.message || 'Something went wrong. Please try again.';
  }

  private async request<T>(
    path: string,
    options: RequestOptions = {},
    retried = false,
  ): Promise<T> {
    const { method = 'GET', body, auth = true } = options;

    try {
      return await firstValueFrom(
        this.http.request<T>(method, `${this.apiBaseSignal()}${path}`, {
          body,
          headers: this.headers(auth),
          responseType: 'json',
        }),
      );
    } catch (error) {
      const status = (error as { status?: number })?.status;
      const canRefresh =
        status === 401 &&
        auth &&
        !retried &&
        !!this.refreshToken() &&
        !path.startsWith('/auth/refresh') &&
        !path.startsWith('/auth/login') &&
        !path.startsWith('/auth/register') &&
        !path.startsWith('/auth/verify-2fa');

      if (canRefresh && (await this.tryRefresh())) {
        return this.request<T>(path, options, true);
      }

      throw new Error(this.errorMessage(error));
    }
  }

  private async tryRefresh(): Promise<boolean> {
    try {
      const result = await firstValueFrom(
        this.http.post<TokenPair>(`${this.apiBaseSignal()}/auth/refresh`, {
          refresh_token: this.refreshToken(),
        }),
      );
      this.setTokens(result.access_token, result.refresh_token);
      return true;
    } catch {
      this.clearSession();
      return false;
    }
  }

  // ------------------------------------------------------------------
  // Authentication endpoints
  // ------------------------------------------------------------------
  async register(email: string, password: string, fullName: string | null): Promise<User> {
    return this.request<User>('/auth/register', {
      method: 'POST',
      body: { email, password, full_name: fullName },
      auth: false,
    });
  }

  async login(email: string, password: string): Promise<LoginResponse> {
    this.pendingEmail.set(email);
    const result = await this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: { email, password },
      auth: false,
    });

    if (result.requires_2fa) {
      this.challengeToken.set(result.challenge_token ?? null);
      this.challengeEmailSent.set(result.email_code_sent === true);
      return result;
    }

    if (result.access_token && result.refresh_token) {
      this.setTokens(result.access_token, result.refresh_token);
      await this.loadUser();
    }
    return result;
  }

  async verifyChallenge(code: string): Promise<TokenPair> {
    const challenge = this.challengeToken();
    if (!challenge) {
      throw new Error('No two-factor challenge is in progress. Please sign in again.');
    }

    const result = await this.request<TokenPair>('/auth/verify-2fa', {
      method: 'POST',
      body: { challenge_token: challenge, code },
      auth: false,
    });

    this.challengeToken.set(null);
    this.challengeEmailSent.set(false);
    this.setTokens(result.access_token, result.refresh_token);
    await this.loadUser();
    return result;
  }

  async loadUser(): Promise<User> {
    const result = await this.request<User>('/auth/me');
    this.user.set(result);
    return result;
  }

  async refresh(): Promise<TokenPair> {
    const result = await this.request<TokenPair>('/auth/refresh', {
      method: 'POST',
      body: { refresh_token: this.refreshToken() },
      auth: false,
    });
    this.setTokens(result.access_token, result.refresh_token);
    return result;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.clearSession();
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request('/auth/change-password', {
      method: 'POST',
      body: { current_password: currentPassword, new_password: newPassword },
    });
  }

  // ------------------------------------------------------------------
  // Two-factor endpoints
  // ------------------------------------------------------------------
  async setupTwoFactor(): Promise<TwoFactorSetup> {
    return this.request<TwoFactorSetup>('/auth/2fa/setup', { method: 'POST' });
  }

  async confirmTwoFactor(code: string): Promise<BackupCodes> {
    return this.request<BackupCodes>('/auth/2fa/confirm', {
      method: 'POST',
      body: { code },
    });
  }

  async twoFactorStatus(): Promise<TwoFactorStatus> {
    return this.request<TwoFactorStatus>('/auth/2fa/status');
  }

  async disableTwoFactor(password: string, code: string): Promise<void> {
    await this.request('/auth/2fa/disable', {
      method: 'POST',
      body: { password, code },
    });
  }

  async regenerateBackupCodes(code: string): Promise<BackupCodes> {
    return this.request<BackupCodes>('/auth/2fa/backup-codes/regenerate', {
      method: 'POST',
      body: { code },
    });
  }
}
