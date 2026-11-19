
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.exceptions import TokenError, unauthorized
from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User
from app.services import user_service

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise unauthorized("Not authenticated")

    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise unauthorized() from exc

    user = user_service.get_by_id(db, payload["sub"])
    if user is None:
        raise unauthorized()

    if not user.is_active:
        raise unauthorized("Account is disabled")

    return user


def get_current_superuser(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_superuser:
        raise unauthorized("Insufficient permissions")
    return current_user
