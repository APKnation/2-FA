
import base64
import io
import secrets

import pyotp
import qrcode
from fastapi import HTTPException, status
from qrcode.image.svg import SvgImage
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.models.user import User


def generate_secret() -> str:
    return pyotp.random_base32()


def _totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=settings.TOTP_DIGITS,
        interval=settings.TOTP_INTERVAL,
    )


def build_provisioning_uri(secret: str, email: str) -> str:
    return _totp(secret).provisioning_uri(name=email, issuer_name=settings.TOTP_ISSUER_NAME)


def generate_qrcode_data_uri(provisioning_uri: str) -> str:
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image(image_factory=SvgImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def generate_backup_codes(count: int | None = None) -> list[str]:
    count = count or settings.BACKUP_CODES_COUNT
    return [
        "-".join(secrets.token_hex(2) for _ in range(4)).upper()
        for _ in range(count)
    ]


def normalize_code(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def verify_totp(secret: str | None, code: str) -> bool:
    if not secret:
        return False
    return _totp(secret).verify(normalize_code(code), valid_window=settings.TOTP_WINDOW)


def verify_backup_code(db: Session, user: User, code: str) -> bool:
    """Check a single-use backup code and consume it on success."""
    target = normalize_code(code)
    for index, hashed in enumerate(user.backup_codes):
        if verify_password(target, hashed):
            user.backup_codes = user.backup_codes[:index] + user.backup_codes[index + 1 :]
            db.commit()
            return True
    return False


# ---------------------------------------------------------------------------
# Flow helpers
# ---------------------------------------------------------------------------
def setup(db: Session, user: User) -> dict:
    """Start enrolment: store a pending secret, not yet enabled."""
    secret = generate_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    db.commit()

    uri = build_provisioning_uri(secret, user.email)
    return {
        "secret": secret,
        "provisioning_uri": uri,
        "qrcode": generate_qrcode_data_uri(uri),
    }


def confirm(db: Session, user: User, code: str) -> list[str]:
    """Verify the pending secret and enable 2FA, issuing backup codes."""
    if not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA setup was not started")

    if not verify_totp(user.totp_secret, code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authentication code")

    user.totp_enabled = True
    codes = generate_backup_codes()
    user.backup_codes = [hash_password(code) for code in codes]
    db.commit()
    return codes


def disable(db: Session, user: User, password: str, code: str) -> None:
    """Disable 2FA after confirming the password and a valid code."""
    if not user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Two-factor authentication is not enabled")

    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect password")

    if not verify_totp(user.totp_secret, code) and not verify_backup_code(db, user, code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authentication code")

    user.totp_secret = None
    user.totp_enabled = False
    user.backup_codes = []
    db.commit()


def regenerate_backup_codes(db: Session, user: User, code: str) -> list[str]:
    if not user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Two-factor authentication is not enabled")

    if not verify_totp(user.totp_secret, code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authentication code")

    codes = generate_backup_codes()
    user.backup_codes = [hash_password(code) for code in codes]
    db.commit()
    return codes
