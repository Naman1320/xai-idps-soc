"""
Feedback and audit log models for analyst disposition tracking.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(50), nullable=True)  # Username or ID
    disposition = Column(String(30), nullable=False)  # true_positive, false_positive, unknown
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    alert = relationship("Alert", back_populates="feedback_entries")


class ResponseLog(Base):
    __tablename__ = "response_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    action_type = Column(String(50), nullable=False)  # notify, escalate, tag, dismiss
    target = Column(String(100), nullable=True)
    result = Column(String(50), default="success")
    triggered_by = Column(String(50), default="analyst")
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
