"""
Authentication schemas for JWT token generation and login.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "employee"


class RoleUpdateRequest(BaseModel):
    role: str


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

