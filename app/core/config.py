
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "SecureAuth"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # --- Database -----------------------------------------------------------
    # Any SQLAlchemy URL works. PostgreSQL is recommended for production:
    #   postgresql+psycopg://user:password@localhost:5432/secureauth
    DATABASE_URL: str = "sqlite:///./secureauth.db"
    # Convenience for local development. Set to False when using Alembic.
    AUTO_CREATE_TABLES: bool = True

    # --- Security / JWT -----------------------------------------------------
    # IMPORTANT: override this with a long random value in production.
    SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Short-lived token that authorizes the second factor step only.
    CHALLENGE_TOKEN_EXPIRE_MINUTES: int = 5

    # --- Two-factor authentication (TOTP) ----------------------------------
    TOTP_ISSUER_NAME: str = "SecureAuth"
    TOTP_DIGITS: int = 6
    TOTP_INTERVAL: int = 30
    # Allowed clock drift, in intervals (1 = +/- 30 seconds).
    TOTP_WINDOW: int = 1
    BACKUP_CODES_COUNT: int = 10

    # --- Brute-force protection --------------------------------------------
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 15

    # --- CORS ---------------------------------------------------------------
    CORS_ORIGINS: str = "*"

    # --- Email (SMTP) — used to send the 2FA verification code -------------
    MAIL_HOST: str = ""
    MAIL_PORT: int = 587
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = ""
    MAIL_USE_TLS: bool = True
    MAIL_USE_SSL: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()
