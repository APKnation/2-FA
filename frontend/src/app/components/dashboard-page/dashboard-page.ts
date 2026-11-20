import { Component, OnInit, signal } from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../services/toast.service';
import { TwoFactorStatus, User } from '../../models';
import { TwoFactorModal } from '../two-factor-modal/two-factor-modal';
import { PasswordModal } from '../password-modal/password-modal';

type ModalKind = 'none' | 'setup' | 'password' | 'disable' | 'regenerate' | 'codes';

@Component({
  selector: 'app-dashboard-page',
  imports: [TwoFactorModal, PasswordModal],
  templateUrl: './dashboard-page.html',
  styleUrl: './dashboard-page.css',
})
export class DashboardPage implements OnInit {
  protected user = signal<User | null>(null);
  protected status = signal<TwoFactorStatus | null>(null);
  protected loading = signal(true);
  protected loadError = signal<string | null>(null);

  protected modal = signal<ModalKind>('none');
  protected backupCodes = signal<string[]>([]);
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  protected disablePassword = '';
  protected disableCode = '';
  protected regenerateCode = '';

  constructor(
    private auth: AuthService,
    private router: Router,
    private toast: ToastService,
  ) {}

  ngOnInit(): void {
    void this.load();
  }

  protected async load(): Promise<void> {
    this.loading.set(true);
    this.loadError.set(null);
    try {
      const [profile, twoFactor] = await Promise.all([
        this.auth.loadUser(),
        this.auth.twoFactorStatus(),
      ]);
      this.user.set(profile);
      this.status.set(twoFactor);
    } catch (err) {
      this.loadError.set((err as Error).message);
    } finally {
      this.loading.set(false);
    }
  }

  protected async refreshStatus(): Promise<void> {
    try {
      this.status.set(await this.auth.twoFactorStatus());
    } catch {
      // The status card simply keeps its previous value.
    }
  }

  protected async reloadUser(): Promise<void> {
    try {
      this.user.set(await this.auth.loadUser());
    } catch {
      // Ignore; the next full load will refresh it.
    }
  }

  protected initials(): string {
    const name = this.user()?.full_name?.trim();
    if (!name) {
      return this.user()?.email?.[0]?.toUpperCase() ?? '?';
    }
    return name
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() ?? '')
      .join('');
  }

  protected memberSince(): string {
    const created = this.user()?.created_at;
    if (!created) {
      return '';
    }
    return new Date(created).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }

  protected openModal(kind: ModalKind): void {
    this.error.set(null);
    this.modal.set(kind);
  }

  protected closeModal(): void {
    this.modal.set('none');
    this.error.set(null);
    this.disablePassword = '';
    this.disableCode = '';
    this.regenerateCode = '';
    void this.refreshStatus();
    void this.reloadUser();
  }

  protected async submitDisable(): Promise<void> {
    if (!this.disablePassword || !this.disableCode.trim()) {
      this.error.set('Enter your password and a current authentication code.');
      return;
    }

    this.busy.set(true);
    this.error.set(null);
    try {
      await this.auth.disableTwoFactor(this.disablePassword, this.disableCode.trim());
      this.toast.success('Two-factor authentication disabled.');
      this.modal.set('none');
      this.disablePassword = '';
      this.disableCode = '';
      await this.refreshStatus();
      await this.reloadUser();
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  protected async submitRegenerate(): Promise<void> {
    if (!this.regenerateCode.trim()) {
      this.error.set('Enter a current authentication code.');
      return;
    }

    this.busy.set(true);
    this.error.set(null);
    try {
      const result = await this.auth.regenerateBackupCodes(this.regenerateCode.trim());
      this.backupCodes.set(result.codes);
      this.modal.set('codes');
      await this.refreshStatus();
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  protected copyCodes(): void {
    void navigator.clipboard?.writeText(this.backupCodes().join('\n'));
    this.toast.success('Backup codes copied to clipboard.');
  }

  protected downloadCodes(): void {
    const content = [
      'SecureAuth backup codes',
      'Generated: ' + new Date().toLocaleString(),
      '',
      ...this.backupCodes(),
      '',
      'Each code can be used once. Store them somewhere safe.',
    ].join('\n');

    const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'secureauth-backup-codes.txt';
    anchor.click();
    URL.revokeObjectURL(url);
  }

  protected logout(): void {
    void this.auth.logout().then(() => this.router.navigateByUrl('/login'));
  }
}
