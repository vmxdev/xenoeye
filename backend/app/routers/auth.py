from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User, UserPreference
from ..schemas import PasswordChange, PreferenceIn, PreferenceOut, Token, UserOut
from ..security import create_access_token, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> Token:
    user = db.scalar(select(User).where(User.email == form.username.lower()))
    if user is None or not user.is_active or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return Token(access_token=create_access_token(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/change-password", status_code=204)
def change_password(
    payload: PasswordChange,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    db.commit()


@router.get("/preferences", response_model=PreferenceOut)
def get_preferences(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> UserPreference:
    preference = db.get(UserPreference, user.id)
    if preference is None:
        preference = UserPreference(user_id=user.id, dashboard={}, theme="dark")
        db.add(preference)
        db.commit()
        db.refresh(preference)
    return preference


@router.put("/preferences", response_model=PreferenceOut)
def update_preferences(
    payload: PreferenceIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserPreference:
    preference = db.get(UserPreference, user.id) or UserPreference(user_id=user.id)
    preference.dashboard = payload.dashboard
    preference.theme = payload.theme
    db.add(preference)
    db.commit()
    db.refresh(preference)
    return preference

