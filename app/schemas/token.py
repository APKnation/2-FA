
from pydantic import BaseModel, Field


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")


class LoginResponse(BaseModel):
    """Returned by /auth/login.

    Either a full token pair (2FA disabled) or a challenge token plus
    ``requires_2fa=True`` (2FA enabled).
    """

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    requires_2fa: bool = False
    challenge_token: str | None = None
    message: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str
