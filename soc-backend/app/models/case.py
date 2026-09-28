"""
Case management ORM models for incident triage and investigations.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base

# Association table for Cases and Alerts
case_alerts = Table(
    "case_alerts",
    Base.metadata,
    Column("case_id", String(36), ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
)


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(200), nullable=False)
    status = Column(String(20), default="open", nullable=False)  # open, investigating, resolved, closed
    severity = Column(String(20), default="medium", nullable=False)  # critical, high, medium, low
    assigned_to = Column(String(50), nullable=True)  # Username or user id
    notes = Column(Text, nullable=True)
    disposition = Column(String(30), nullable=True)  # true_positive, false_positive, benign_activity, undetermined
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    alerts = relationship("Alert", secondary=case_alerts, back_populates="cases")
