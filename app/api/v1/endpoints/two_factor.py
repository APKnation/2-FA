
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas import (
    BackupCodesResponse,
    CodeRequest,
    TwoFactorDisableRequest,
    TwoFactorSetupResponse,
    TwoFactorStatusResponse,
)
from app.services import two_factor_service

router = APIRouter(prefix="/auth/2fa", tags=["two-factor"])


@router.post("/setup", response_model=TwoFactorSetupResponse)
def setup(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Generate a new TOTP secret and QR code. 2FA is enabled by /confirm."""
    return two_factor_service.setup(db, current_user)


@router.post("/confirm", response_model=BackupCodesResponse)
def confirm(
    payload: CodeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    codes = two_factor_service.confirm(db, current_user, payload.code)
    return {"codes": codes}


@router.get("/status", response_model=TwoFactorStatusResponse)
def status(current_user: User = Depends(get_current_user)) -> dict:
    return {
        "enabled": current_user.totp_enabled,
        "backup_codes_remaining": len(current_user.backup_codes),
    }


@router.post("/disable")
def disable(
    payload: TwoFactorDisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    two_factor_service.disable(db, current_user, payload.password, payload.code)
    return {"message": "Two-factor authentication disabled"}


@router.post("/backup-codes/regenerate", response_model=BackupCodesResponse)
def regenerate_backup_codes(
    payload: CodeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    codes = two_factor_service.regenerate_backup_codes(db, current_user, payload.code)
    return {"codes": codes}
