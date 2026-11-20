import { Routes } from '@angular/router';

import { AuthPage } from './components/auth-page/auth-page';
import { ChallengePage } from './components/challenge-page/challenge-page';
import { DashboardPage } from './components/dashboard-page/dashboard-page';
import { requireAuthGuard } from './guards/require-auth.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
  { path: 'login', component: AuthPage, data: { mode: 'login' } },
  { path: 'register', component: AuthPage, data: { mode: 'register' } },
  { path: 'challenge', component: ChallengePage },
  { path: 'dashboard', component: DashboardPage, canActivate: [requireAuthGuard] },
  { path: '**', redirectTo: 'dashboard' },
];
