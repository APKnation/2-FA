
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.models.user import User


def get_by_email(db: Session, email: str) -> User | None:
    statement = select(User).where(func.lower(User.email) == email.lower())
    return db.execute(statement).scalar_one_or_none()


def get_by_id(db: Session, user_id: str | uuid.UUID) -> User | None:
    return db.get(User, uuid.UUID(str(user_id)))


def create_user(db: Session, email: str, password: str, full_name: str | None = None) -> User:
    if get_by_email(db, email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    user = User(
        email=email.lower(),
        full_name=full_name,
        hashed_password=hash_password(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    # SQLite returns naive datetimes even for timezone-aware columns.
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def register_failed_attempt(db: Session, user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
    db.commit()


def clear_failed_attempts(db: Session, user: User) -> None:
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()


def touch_last_login(db: Session, user: User) -> None:
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()


def set_password(db: Session, user: User, password: str) -> None:
    user.hashed_password = hash_password(password)
    user.token_version += 1
    db.commit()


def bump_token_version(db: Session, user: User) -> None:
    user.token_version += 1
    db.commit()
