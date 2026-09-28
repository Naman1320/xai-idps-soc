"""
Pydantic schemas for Case management.
"""

from datetime import datetime

from app.schemas.alert_schema import AlertResponse
from pydantic import BaseModel, Field


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    severity: str = Field(default="medium", description="critical, high, medium, low")
    assigned_to: str | None = "analyst"
    notes: str | None = None
    alert_ids: list[str] | None = []


class CaseUpdate(BaseModel):
    title: str | None = None
    status: str | None = Field(
        None, description="open, investigating, resolved, closed"
    )
    severity: str | None = None
    assigned_to: str | None = None
    notes: str | None = None
    disposition: str | None = Field(
        None, description="true_positive, false_positive, benign_activity, undetermined"
    )
    alert_ids: list[str] | None = None


class CaseResponse(BaseModel):
    id: str
    title: str
    status: str
    severity: str
    assigned_to: str | None = None
    notes: str | None = None
    disposition: str | None = None
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertResponse] | None = []

    class Config:
        from_attributes = True


class CaseListResponse(BaseModel):
    cases: list[CaseResponse]
    total: int
