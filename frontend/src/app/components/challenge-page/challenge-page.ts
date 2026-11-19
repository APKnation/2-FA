
import { Component, OnInit, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../services/toast.service';

@Component({
  selector: 'app-challenge-page',
  imports: [RouterLink],
  templateUrl: './challenge-page.html',
  styleUrl: './challenge-page.css',
})
export class ChallengePage implements OnInit {
  protected code = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);
  protected useBackup = signal(false);

  constructor(
    private auth: AuthService,
    private router: Router,
    private toast: ToastService
  ) {}

  ngOnInit(): void {
    if (!this.auth.challengeToken()) {
      void this.router.navigateByUrl('/login');
    }
  }

  protected get email(): string | null {
    return this.auth.pendingEmail();
  }

  protected toggleMode(): void {
    this.useBackup.update((value) => !value);
    this.error.set(null);
  }

  protected async submit(): Promise<void> {
    this.error.set(null);
    const trimmed = this.code.trim();

    if (trimmed.length < 4) {
      this.error.set(
        this.useBackup()
          ? 'Enter a backup code.'
          : 'Enter the 6-digit code from your authenticator app.'
      );
      return;
    }

    this.busy.set(true);
    try {
      await this.auth.verifyChallenge(trimmed);
      this.toast.success('Signed in successfully.');
      void this.router.navigateByUrl('/dashboard');
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  protected cancel(): void {
    this.auth.challengeToken.set(null);
    void this.router.navigateByUrl('/login');
  }
}
