import { Component, effect, input, output, signal } from '@angular/core';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../services/toast.service';
import { TwoFactorSetup } from '../../models';

@Component({
  selector: 'app-two-factor-modal',
  templateUrl: './two-factor-modal.html',
  styleUrl: './two-factor-modal.css',
})
export class TwoFactorModal {
  readonly open = input.required<boolean>();
  readonly closed = output<void>();

  protected step = signal<'qr' | 'codes'>('qr');
  protected setup = signal<TwoFactorSetup | null>(null);
  protected codes = signal<string[]>([]);
  protected code = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  constructor(
    private auth: AuthService,
    private toast: ToastService,
  ) {
    effect(() => {
      if (this.open()) {
        void this.start();
      }
    });
  }

  protected async start(): Promise<void> {
    this.step.set('qr');
    this.setup.set(null);
    this.codes.set([]);
    this.code = '';
    this.error.set(null);
    this.busy.set(true);

    try {
      this.setup.set(await this.auth.setupTwoFactor());
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  protected async confirm(): Promise<void> {
    this.error.set(null);
    const trimmed = this.code.trim();
    if (trimmed.length < 4) {
      this.error.set('Enter the code from your authenticator app.');
      return;
    }

    this.busy.set(true);
    try {
      const result = await this.auth.confirmTwoFactor(trimmed);
      this.codes.set(result.codes);
      this.step.set('codes');
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  protected close(): void {
    this.closed.emit();
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
    this.toast.success('Copied to clipboard.');
  }

  protected copyCodes(): void {
    void navigator.clipboard?.writeText(this.codes().join('\n'));
    this.toast.success('Backup codes copied to clipboard.');
  }

  protected downloadCodes(): void {
    const content = [
      'SecureAuth backup codes',
      'Generated: ' + new Date().toLocaleString(),
      '',
      ...this.codes(),
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
}
