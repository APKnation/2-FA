
# SecureAuth — Demo Frontend

Angular 21 demo interface for the SecureAuth FastAPI backend. It exercises the complete
authentication and two-factor authentication flow against the API.

## Features

- Sign in / create account with validation and inline errors.
- Two-step verification screen for TOTP and single-use backup codes.
- Dashboard with profile details and 2FA status.
- 2FA enrolment: QR code (SVG), manual secret entry, TOTP confirmation, and backup
  codes with copy/download.
- Regenerate and disable 2FA.
- Change password and sign out.
- Toast notifications and session restore via refresh token.
- Configurable API base URL (defaults to `/api/v1` through the dev-server proxy).

## Running

Start the backend first:

```bash
# from the project root
uvicorn app.main:app --reload
```

Then start the Angular dev server:

```bash
cd frontend
npm install   # first time only
npm start
```

Open <http://localhost:4200>. The dev server proxies `/api` to `http://localhost:8000`,
so the default API base `/api/v1` works without CORS issues.

To call the backend directly instead, open the **API** dialog in the header and set the
base URL to `http://localhost:8000/api/v1` (the backend allows CORS by default).

## Brand colors

The theme is defined in `src/styles.css`:

| Token | Value | Usage |
| --- | --- | --- |
| `--color-brand` | `#176571` | Primary actions, highlights |
| `--color-navy` | `#1A3567` | Headings, primary buttons |
| `#ffffff` | white | Cards and surfaces |

## Structure

```
src/app/
├── components/
│   ├── auth-page/          # sign in / create account
│   ├── challenge-page/     # second-factor verification
│   ├── dashboard-page/     # profile, 2FA management, session
│   ├── two-factor-modal/   # QR enrolment + backup codes
│   ├── password-modal/     # change password
│   ├── toast-container/    # notifications
│   └── logo/
├── guards/                 # auth route guard
├── services/               # AuthService (API) and ToastService
├── models.ts               # API types
├── app.ts / app.html       # shell with header and API settings
└── app.routes.ts
```

## Build

```bash
npm run build   # production bundle in dist/
npm test        # unit tests (Vitest)
```
