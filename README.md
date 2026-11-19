
# SecureAuth — FastAPI Two-Factor Authentication API

A reusable authentication service built with FastAPI, SQLAlchemy 2.0, and Pydantic v2.
It provides email/password authentication with JWT access and refresh tokens, TOTP-based
two-factor authentication (authenticator apps + single-use backup codes), brute-force
lockout protection, and password rotation.

## Features

- **Registration and login** with Argon2id password hashing (`pwdlib`).
- **JWT access tokens** (short-lived) and **refresh tokens** (long-lived, rotating).
  Refresh tokens carry a `token_version` claim that is bumped on logout or password
  change, so all previously issued refresh tokens are invalidated instantly.
- **TOTP two-factor authentication** via `pyotp`:
  - `POST /auth/2fa/setup` returns a secret, an `otpauth://` URI and an SVG QR code.
  - `POST /auth/2fa/confirm` verifies a code, enables 2FA and returns 10 single-use
    backup codes (Argon2id-hashed at rest).
  - Login then returns a short-lived **challenge token**; the second factor is verified
    with `POST /auth/verify-2fa`, which exchanges it for real tokens.
  - Backup codes are case-insensitive, ignore dashes/spaces, and are consumed on use.
  - 2FA can be disabled with the account password plus a current TOTP or backup code.
- **Brute-force protection**: accounts lock for `LOCKOUT_MINUTES` after
  `MAX_FAILED_LOGIN_ATTEMPTS` failed logins.
- **Alembic migrations** for PostgreSQL/SQLite, plus automatic table creation for
  local development.
- **Pytest suite** covering registration, login, lockout, refresh, logout, password
  change, and the full 2FA lifecycle.
- **Python SDK** in `sdk/secureauth` for integrating the API into other services.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and adjust the values. The most important settings:

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./secureauth.db` | Any SQLAlchemy URL. Use PostgreSQL in production. |
| `SECRET_KEY` | dev placeholder | **Must** be a long random value in production (`openssl rand -hex 32`). |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime. |
| `CHALLENGE_TOKEN_EXPIRE_MINUTES` | `5` | Lifetime of the intermediate 2FA challenge token. |
| `TOTP_ISSUER_NAME` | `SecureAuth` | Issuer shown in authenticator apps. |
| `TOTP_WINDOW` | `1` | Allowed TOTP clock drift (intervals). |
| `BACKUP_CODES_COUNT` | `10` | Number of single-use backup codes. |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `5` | Failed logins before lockout. |
| `LOCKOUT_MINUTES` | `15` | Lockout duration. |
| `AUTO_CREATE_TABLES` | `True` | Create tables on startup (development only). |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins. |
| `MAIL_HOST` / `MAIL_PORT` / `MAIL_USERNAME` / `MAIL_PASSWORD` | — | SMTP server used to send the 2FA code (see below). |
| `MAIL_FROM` | — | From address of the mail. |
| `MAIL_USE_TLS` / `MAIL_USE_SSL` | — | TLS options for the SMTP connection. |

## Running

```bash
uvicorn app.main:app --reload
```

Interactive API docs are available at `http://localhost:8000/docs`.

### Database migrations

```bash
# Create a new migration after changing models
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head
```

For production, set `AUTO_CREATE_TABLES=False` and manage the schema exclusively
through Alembic.

## API endpoints

Base path: `/api/v1`

### Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/auth/register` | — | Create an account. |
| `POST` | `/auth/login` | — | First factor. Returns tokens, or `requires_2fa` + `challenge_token`. |
| `POST` | `/auth/verify-2fa` | — | Second factor. Exchanges a challenge token + code for tokens. |
| `POST` | `/auth/refresh` | — | Exchange a refresh token for a new token pair. |
| `POST` | `/auth/logout` | Bearer | Invalidate all refresh tokens for the current user. |
| `GET` | `/auth/me` | Bearer | Return the current user. |
| `POST` | `/auth/change-password` | Bearer | Change password (invalidates refresh tokens). |

### Two-factor authentication

All endpoints require a valid access token.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/auth/2fa/setup` | Generate a TOTP secret, `otpauth://` URI and SVG QR code. |
| `POST` | `/auth/2fa/confirm` | Verify a TOTP code, enable 2FA, return backup codes. |
| `GET` | `/auth/2fa/status` | Report whether 2FA is enabled and how many backup codes remain. |
| `POST` | `/auth/2fa/disable` | Disable 2FA (password + current code required). |
| `POST` | `/auth/2fa/backup-codes/regenerate` | Replace backup codes (current TOTP required). |

## Two-factor authentication flow

```bash
# 1. Register and log in
curl -X POST localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"Sup3r-Secret!"}'

# 2. Start 2FA enrolment (use the access token from login)
curl -X POST localhost:8000/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# -> { "secret": "...", "provisioning_uri": "otpauth://...", "qrcode": "data:image/svg+xml;base64,..." }

# 3. Scan the QR code with Google Authenticator / Authy, then confirm
CODE=$(oathtool --totp -b "BASE32SECRET")
curl -X POST localhost:8000/api/v1/auth/2fa/confirm \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"code\":\"$CODE\"}"
# -> { "codes": ["XXXX-XXXX-XXXX-XXXX", ...] }  # store these safely

# 4. Log in: first factor returns a challenge token
curl -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"Sup3r-Secret!"}'
# -> { "requires_2fa": true, "challenge_token": "..." }

# 5. Second factor returns the real tokens
curl -X POST localhost:8000/api/v1/auth/verify-2fa \
  -H 'Content-Type: application/json' \
  -d "{\"challenge_token\":\"$CHALLENGE_TOKEN\",\"code\":\"$CODE\"}"
```

## Email delivery of the 2FA code

When SMTP is configured, the two-factor verification code is emailed to the
registered email address as soon as the user starts signing in with 2FA.

Add this to `.env`:

```bash
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=smtp-user
MAIL_PASSWORD=smtp-pass
MAIL_FROM=noreply@secureauth.local
MAIL_USE_TLS=True   # or use SMTP_SSL / false depending on your provider
```

Notes:

- If mail fails or SMTP is not configured, `email_code_sent` is `false` and sign-in
  still works — the user uses their authenticator app or a backup code.
- The emailed code is the current TOTP code (valid for ~30 seconds), so the user can
  also copy it into the **Two-step verification** screen.
- For local development you can point `MAIL_HOST` at a dummy SMTP sink (e.g.
  `maildev`) or use Postfix.

## SDK

```python
from secureauth import SecureAuthClient

with SecureAuthClient("http://localhost:8000") as client:
    client.register("user@example.com", "Sup3r-Secret!")

    step = client.login("user@example.com", "Sup3r-Secret!")
    if step["requires_2fa"]:
        client.verify_2fa(step["challenge_token"], input("TOTP code: "))

    print(client.me())
```

`login_with_2fa(email, password, code)` performs both factors in a single call.

## Tests

```bash
pytest
```

The suite uses an isolated in-memory SQLite database and covers the complete
authentication and 2FA lifecycle (26 tests).

## Project structure

```
app/
├── api/v1/           # routers and endpoints
├── core/             # config, security (JWT/passwords), dependencies, exceptions
├── db/               # SQLAlchemy base and session
├── models/           # ORM models
├── schemas/          # Pydantic request/response models
├── services/         # business logic (auth, users, 2FA)
└── main.py           # application entry point
alembic/              # migrations
sdk/secureauth/       # Python client
tests/                # pytest suite
```

## Security notes

- Always set a strong, unique `SECRET_KEY` in production and serve the API over HTTPS.
- Passwords are hashed with Argon2id; backup codes are hashed with the same algorithm.
- Refresh tokens are invalidated on logout and password change via `token_version`.
- Failed logins are rate-limited per account. For multi-instance deployments, back the
  lockout counter with a shared store (e.g. Redis) instead of the database.
- Access tokens are stateless JWTs and remain valid until expiry; keep
  `ACCESS_TOKEN_EXPIRE_MINUTES` short and prefer refresh rotation.
