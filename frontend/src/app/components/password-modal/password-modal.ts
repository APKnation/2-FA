import { Component, input, output, signal } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../services/toast.service';

@Component({
  selector: 'app-password-modal',
  imports: [ReactiveFormsModule],
  templateUrl: './password-modal.html',
  styleUrl: './password-modal.css',
})
export class PasswordModal {
  readonly open = input.required<boolean>();
  readonly closed = output<void>();

  protected form: FormGroup;
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  constructor(
    private fb: FormBuilder,
    private auth: AuthService,
    private toast: ToastService,
  ) {
    this.form = this.fb.group({
      currentPassword: ['', [Validators.required]],
      newPassword: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', [Validators.required]],
    });
  }

  protected close(): void {
    this.form.reset();
    this.error.set(null);
    this.closed.emit();
  }

  protected async submit(): Promise<void> {
    this.error.set(null);

    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const { currentPassword, newPassword, confirmPassword } = this.form.value as {
      currentPassword: string;
      newPassword: string;
      confirmPassword: string;
    };

    if (newPassword !== confirmPassword) {
      this.error.set('New passwords do not match.');
      return;
    }

    this.busy.set(true);
    try {
      await this.auth.changePassword(currentPassword, newPassword);
      this.toast.success('Password changed successfully.');
      this.close();
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }
}
