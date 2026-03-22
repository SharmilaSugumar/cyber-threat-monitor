from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

from ..database import get_db
from ..models.models import User, LoginHistory
from ..core.security import verify_password, create_access_token, decode_token, get_password_hash

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    token_type:   str
    user:         dict

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email:     Optional[str] = None

class CreateUser(BaseModel):
    username:  str
    email:     str
    full_name: str
    password:  str
    role:      str = "analyst"


# ── get_current_user MUST be defined BEFORE any route that uses it ────────────
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db:    Session = Depends(get_db)
) -> User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    return user


# ── Login ─────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
def login(
    request:   Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db:        Session = Depends(get_db)
):
    user    = db.query(User).filter(User.username == form_data.username).first()
    ip      = request.client.host if request.client else "unknown"
    ua      = request.headers.get("user-agent", "")[:200]
    success = bool(user and verify_password(form_data.password, user.hashed_password))

    log = LoginHistory(
        user_id    = user.id if user else None,
        ip_address = ip,
        user_agent = ua,
        success    = success,
    )
    db.add(log)

    if not success:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.username, "role": user.role})
    return {
        "access_token": token,
        "token_type":   "bearer",
        "user": {
            "id":         user.id,
            "username":   user.username,
            "email":      user.email,
            "full_name":  user.full_name,
            "role":       user.role,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
    }


# ── Get current user profile ──────────────────────────────────────────────────
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id":         current_user.id,
        "username":   current_user.username,
        "email":      current_user.email,
        "full_name":  current_user.full_name,
        "role":       current_user.role,
        "created_at": current_user.created_at.isoformat(),
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
    }


# ── Update profile ────────────────────────────────────────────────────────────
@router.put("/me")
def update_me(
    data:         UserUpdate,
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    if data.full_name:
        current_user.full_name = data.full_name
    if data.email:
        current_user.email = data.email
    db.commit()
    return {"message": "Profile updated"}


# ── Login history ─────────────────────────────────────────────────────────────
@router.get("/login-history")
def get_login_history(
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    history = (
        db.query(LoginHistory)
        .filter(LoginHistory.user_id == current_user.id)
        .order_by(LoginHistory.timestamp.desc())
        .limit(20)
        .all()
    )
    return [
        {
            "timestamp":  h.timestamp.isoformat(),
            "ip_address": h.ip_address,
            "success":    h.success,
        }
        for h in history
    ]


# ── Logout ────────────────────────────────────────────────────────────────────
@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    return {"message": f"Goodbye {current_user.username}"}


@router.post("/register")
def register(data: CreateUser, db: Session = Depends(get_db)):
    """Public registration — no auth required."""
    existing = db.query(User).filter(User.username == data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(
        username        = data.username,
        email           = data.email,
        full_name       = data.full_name,
        role            = "analyst",
        hashed_password = get_password_hash(data.password),
    )
    db.add(user)
    db.commit()
    return {"message": "Account created successfully"}


# ── List all users (admin only) ───────────────────────────────────────────────
@router.get("/users")
def list_users(
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = db.query(User).all()
    return [
        {
            "id":         u.id,
            "username":   u.username,
            "email":      u.email,
            "full_name":  u.full_name,
            "role":       u.role,
            "is_active":  u.is_active,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]


# ── Create new user (admin only) ──────────────────────────────────────────────
@router.post("/users")
def create_user(
    data:         CreateUser,
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    existing = db.query(User).filter(User.username == data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username        = data.username,
        email           = data.email,
        full_name       = data.full_name,
        role            = data.role,
        hashed_password = get_password_hash(data.password),
    )
    db.add(user)
    db.commit()
    return {"message": f"User {data.username} created successfully"}


# ── Delete user (admin only) ──────────────────────────────────────────────────
@router.delete("/users/{user_id}")
def delete_user(
    user_id:      int,
    current_user: User = Depends(get_current_user),
    db:           Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    db.delete(user)
    db.commit()
    return {"message": f"User {user.username} deleted"}