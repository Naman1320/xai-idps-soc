"""
Pydantic schemas for Case management.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.alert_schema import AlertResponse


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    severity: str = Field(default="medium", description="critical, high, medium, low")
    assigned_to: Optional[str] = "analyst"
    notes: Optional[str] = None
    alert_ids: Optional[List[str]] = []


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = Field(None, description="open, investigating, resolved, closed")
    severity: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    disposition: Optional[str] = Field(None, description="true_positive, false_positive, benign_activity, undetermined")
    alert_ids: Optional[List[str]] = None


class CaseResponse(BaseModel):
    id: str
    title: str
    status: str
    severity: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    disposition: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    alerts: Optional[List[AlertResponse]] = []

    class Config:
        from_attributes = True


class CaseListResponse(BaseModel):
    cases: List[CaseResponse]
    total: int
