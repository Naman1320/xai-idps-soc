"""
Feedback schemas for analyst disposition submissions and audit logs.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class FeedbackCreate(BaseModel):
    disposition: str = Field(..., description="true_positive, false_positive, unknown")
    notes: str | None = None


class FeedbackResponse(BaseModel):
    id: str
    alert_id: str
    user_id: str | None = None
    disposition: str
    notes: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True
