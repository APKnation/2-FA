
from pydantic import BaseModel, Field


CODE_PATTERN = r"^[0-9A-Za-z-]+$"


class CodeRequest(BaseModel):
    """A TOTP code or a backup code."""

    code: str = Field(min_length=4, max_length=32, pattern=CODE_PATTERN)


class ChallengeRequest(BaseModel):
    challenge_token: str
    code: str = Field(min_length=4, max_length=32, pattern=CODE_PATTERN)


class TwoFactorSetupResponse(BaseModel):
    secret: str = Field(description="Base32 TOTP secret for manual entry")
    provisioning_uri: str = Field(description="otpauth:// URI for authenticator apps")
    qrcode: str = Field(description="SVG data URI of the provisioning QR code")


class TwoFactorStatusResponse(BaseModel):
    enabled: bool
    backup_codes_remaining: int


class BackupCodesResponse(BaseModel):
    codes: list[str]
    message: str = (
        "Store these single-use backup codes in a safe place. "
        "They will not be shown again."
    )


class TwoFactorDisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=4, max_length=32, pattern=CODE_PATTERN)
