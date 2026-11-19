
import { Component, input, signal } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../services/toast.service';
import { Logo } from '../logo/logo';

@Component({
  selector: 'app-auth-page',
  imports: [ReactiveFormsModule, RouterLink, Logo],
  templateUrl: './auth-page.html',
  styleUrl: './auth-page.css',
})
export class AuthPage {
  readonly mode = input<'login' | 'register'>('login');

  protected form: FormGroup;
  protected busy = signal(false);
  protected error = signal<string | null>(null);
  protected showPassword = signal(false);

  constructor(
    private fb: FormBuilder,
    protected auth: AuthService,
    private router: Router,
    private toast: ToastService
  ) {
    this.form = this.fb.group({
      fullName: [''],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
      confirmPassword: [''],
    });
  }

  protected isRegister(): boolean {
    return this.mode() === 'register';
  }

  protected togglePassword(): void {
    this.showPassword.update((value) => !value);
  }

  protected goTo(target: 'login' | 'register'): void {
    if (this.mode() !== target) {
      void this.router.navigateByUrl(`/${target}`);
    }
  }

  protected async submit(): Promise<void> {
    this.error.set(null);

    if (this.isRegister()) {
      await this.submitRegister();
      return;
    }
    await this.submitLogin();
  }

  private async submitRegister(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const { fullName, email, password, confirmPassword } = this.form.value as {
      fullName: string;
      email: string;
      password: string;
      confirmPassword: string;
    };

    if (password.length < 8) {
      this.error.set('Password must be at least 8 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      this.error.set('Passwords do not match.');
      return;
    }

    this.busy.set(true);
    try {
      await this.auth.register(email, password, fullName?.trim() || null);
      this.toast.success('Account created. Welcome!');
      await this.login(email, password);
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  private async submitLogin(): Promise<void> {
    if (this.form.get('email')?.invalid || !this.form.value.password) {
      this.form.markAllAsTouched();
      return;
    }

    this.busy.set(true);
    try {
      await this.login(this.form.value.email, this.form.value.password);
    } catch (err) {
      this.error.set((err as Error).message);
    } finally {
      this.busy.set(false);
    }
  }

  private async login(email: string, password: string): Promise<void> {
    const result = await this.auth.login(email, password);
    if (result.requires_2fa) {
      void this.router.navigateByUrl('/challenge');
    } else {
      void this.router.navigateByUrl('/dashboard');
    }
  }
}
