
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas import (
    ChallengeRequest,
    LoginResponse,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserLogin,
    UserResponse,
)
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    return auth_service.register(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
    )


@router.post("/login", response_model=LoginResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> dict:
    return auth_service.login(db, email=payload.email, password=payload.password)


@router.post("/verify-2fa", response_model=LoginResponse)
def verify_2fa(payload: ChallengeRequest, db: Session = Depends(get_db)) -> dict:
    return auth_service.verify_challenge(db, payload.challenge_token, payload.code)


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> dict:
    return auth_service.refresh(db, payload.refresh_token)


@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    auth_service.logout(db, current_user)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post("/change-password")
def change_password(
    payload: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    auth_service.change_password(
        db,
        current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    return {"message": "Password changed. Use your refresh token to obtain new access tokens."}
