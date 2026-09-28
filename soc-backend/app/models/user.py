"""
User ORM model for RBAC authentication.
"""

import uuid
from datetime import datetime

from app.database import Base
from sqlalchemy import Column, DateTime, String


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(
        String(20), default="analyst", nullable=False
    )  # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
