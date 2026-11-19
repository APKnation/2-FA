
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import TokenError
from app.core.security import (
    build_token_pair,
    create_challenge_token,
    decode_token,
    verify_password,
)
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


def login(db: Session, email: str, password: str) -> dict:
    """First factor. Returns a token pair, or a 2FA challenge."""
    user = authenticate(db, email, password)

    if user.totp_enabled:
        return {
            "requires_2fa": True,
            "challenge_token": create_challenge_token(user.id),
            "email_code_sent": send_challenge_code_email(user),
            "message": "Provide a TOTP or backup code to finish authentication",
        }

    return {"requires_2fa": False, **build_token_pair(user.id, user.token_version)}


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
