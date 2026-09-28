"""
Feedback schemas for analyst disposition submissions and audit logs.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class FeedbackCreate(BaseModel):
    disposition: str = Field(..., description="true_positive, false_positive, unknown")
    notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    id: str
    alert_id: str
    user_id: Optional[str] = None
    disposition: str
    notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
