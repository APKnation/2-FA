import { Component, signal } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';

import { AuthService } from './services/auth.service';
import { Logo } from './components/logo/logo';
import { ToastContainer } from './components/toast-container/toast-container';

@Component({
  selector: 'app-root',
  imports: [RouterLink, RouterOutlet, Logo, ToastContainer],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  protected readonly title = signal('SecureAuth');
  protected apiOpen = signal(false);
  protected apiUrl = signal('');

  constructor(protected auth: AuthService) {
    this.apiUrl.set(auth.apiBase());
  }

  openApiSettings(): void {
    this.apiUrl.set(this.auth.apiBase());
    this.apiOpen.set(true);
  }

  saveApiSettings(): void {
    this.auth.setApiBase(this.apiUrl());
    this.apiOpen.set(false);
  }

  logout(): void {
    void this.auth.logout();
  }
}
