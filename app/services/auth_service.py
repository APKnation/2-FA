
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import TokenError
import logging
import secrets
from datetime import timedelta, timezone

logger = logging.getLogger(__name__)

from app.core.security import (
    build_token_pair,
    create_challenge_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.core.config import settings
from app.models.user import utcnow
from app.models.user import User
from app.services import user_service
from app.services import mail
from app.services import two_factor_service


def register(db: Session, email: str, password: str, full_name: str | None = None) -> User:
    return user_service.create_user(db, email=email, password=password, full_name=full_name)


def authenticate(db: Session, email: str, password: str) -> User:
    """Validate credentials, enforcing the failed-attempt lockout."""
    user = user_service.get_by_email(db, email)

    if user is None:
        # Same error as a wrong password to avoid user enumeration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if user_service.is_locked(user):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to too many failed login attempts",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    if not verify_password(password, user.hashed_password):
        user_service.register_failed_attempt(db, user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    user_service.clear_failed_attempts(db, user)
    user_service.touch_last_login(db, user)
    return user


def _generate_email_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def login(db: Session, email: str, password: str) -> dict:
    """First factor. Returns a 2FA challenge secured by an emailed one-time code."""
    user = authenticate(db, email, password)

    otp = _generate_email_otp()
    user.email_otp_hash = hash_password(otp)
    user.email_otp_expires_at = utcnow() + timedelta(
        minutes=settings.CHALLENGE_TOKEN_EXPIRE_MINUTES
    )
    db.commit()

    email_sent = mail.send_verification_code(user.email, otp, user.full_name)
    if settings.DEBUG:
        logger.warning("DEBUG: email OTP for %s is %s", user.email, otp)
    return {
        "requires_2fa": True,
        "challenge_token": create_challenge_token(user.id),
        "email_code_sent": email_sent,
        "message": "Provide the code sent to your email to finish authentication",
    }


def send_challenge_code_email(user: User) -> bool:
    """Email the current TOTP code used for the 2FA step, if mail is configured."""
    if not user.totp_secret:
        return False
    code = two_factor_service.generate_code(user.totp_secret)
    return mail.send_verification_code(user.email, code, user.full_name)


def verify_challenge(db: Session, challenge_token: str, code: str) -> dict:
    """Second factor. Exchanges a challenge token for a real token pair."""
    try:
        payload = decode_token(challenge_token, expected_type="2fa_challenge")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication challenge",
        ) from exc

    user = user_service.get_by_id(db, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication challenge")

    valid = False
    # Email one-time password (primary flow for all users).
    if user.email_otp_hash and user.email_otp_expires_at:
        expires_at = user.email_otp_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if utcnow() <= expires_at and verify_password(
            code.strip(), user.email_otp_hash
        ):
            valid = True
            user.email_otp_hash = None
            user.email_otp_expires_at = None

    # Legacy TOTP / backup codes, kept for backward compatibility.
    if not valid:
        valid = two_factor_service.verify_totp(user.totp_secret, code) or two_factor_service.verify_backup_code(
            db, user, code
        )

    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code")

    user_service.touch_last_login(db, user)
    return {**build_token_pair(user.id, user.token_version)}


def refresh(db: Session, refresh_token: str) -> dict:
    try:
        payload = decode_token(refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from exc

    user = user_service.get_by_id(db, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.get("tv") != user.token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

    return build_token_pair(user.id, user.token_version)


def logout(db: Session, user: User) -> None:
    """Invalidate all refresh tokens issued to this user."""
    user_service.bump_token_version(db, user)


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if current_password == new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current password",
        )

    user_service.set_password(db, user, new_password)
