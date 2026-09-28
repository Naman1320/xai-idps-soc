"""
Authentication and authorization endpoints.
"""

import uuid
from datetime import datetime

from app.database import get_db
from app.middleware.auth_middleware import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth_schema import (
    RoleUpdateRequest,
    Token,
    UserCreateRequest,
    UserLogin,
    UserRegister,
    UserResponse,
)
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user with username and password, returning JWT."""
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        username=user.username,
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return currently logged-in user profile."""
    return current_user


@router.get("/users", response_model=list[UserResponse])
def get_all_users(db: Session = Depends(get_db)):
    """List all user profiles and roles in the platform."""
    return db.query(User).order_by(User.created_at.desc()).all()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user_profile(user_data: UserCreateRequest, db: Session = Depends(get_db)):
    """
    Create a new user profile with a specific role (e.g. admin, manager, employee, analyst, viewer).
    Permits flexible role provisioning for demonstration and operational use.
    """
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{user_data.username}' already exists.",
        )

    # Validate role
    allowed_roles = {"admin", "manager", "employee", "analyst", "viewer"}
    clean_role = user_data.role.lower().strip()
    if clean_role not in allowed_roles:
        clean_role = "employee"

    new_user = User(
        id=str(uuid.uuid4()),
        username=user_data.username.strip(),
        password_hash=hash_password(user_data.password),
        role=clean_role,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.put("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: str, role_data: RoleUpdateRequest, db: Session = Depends(get_db)
):
    """Update an existing user's role."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    allowed_roles = {"admin", "manager", "employee", "analyst", "viewer"}
    clean_role = role_data.role.lower().strip()
    if clean_role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Allowed: {list(allowed_roles)}",
        )

    user.role = clean_role
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_profile(user_id: str, db: Session = Depends(get_db)):
    """Delete a user profile."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user.username == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Default primary admin account cannot be deleted.",
        )

    db.delete(user)
    db.commit()


@router.post("/register", response_model=UserResponse)
def register(register_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user (supports direct registration for demo agility)."""
    existing = db.query(User).filter(User.username == register_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    new_user = User(
        id=str(uuid.uuid4()),
        username=register_data.username,
        password_hash=hash_password(register_data.password),
        role=register_data.role.lower().strip(),
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
